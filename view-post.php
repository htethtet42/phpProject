
<?php
session_start();
require "connect.php";

function e($value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

// Sanitize rich-text HTML before displaying it.
function safePostHtml(string $html): string
{
    $allowed = '<p><br><strong><b><em><i><u><s><h1><h2><h3><h4><blockquote><ul><ol><li><a><img><pre><code><hr><sub><sup>';
    $html = strip_tags($html, $allowed);

    if (!class_exists('DOMDocument')) {
        $html = preg_replace(
            '/\s+on[a-z]+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)/i',
            '',
            $html
        );
        $html = preg_replace('/javascript\s*:/i', '', $html);
        return $html;
    }

    $dom = new DOMDocument('1.0', 'UTF-8');
    $previous = libxml_use_internal_errors(true);

    $dom->loadHTML(
        '<?xml encoding="UTF-8"><div id="post-root">' . $html . '</div>',
        LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD
    );

    libxml_clear_errors();
    libxml_use_internal_errors($previous);

    $root = null;

    foreach ($dom->getElementsByTagName('div') as $candidate) {
        if ($candidate->getAttribute('id') === 'post-root') {
            $root = $candidate;
            break;
        }
    }

    if (!$root) {
        return '';
    }

    $walk = function ($node) use (&$walk) {
        $children = [];

        foreach ($node->childNodes as $child) {
            $children[] = $child;
        }

        foreach ($children as $child) {
            if ($child->nodeType !== XML_ELEMENT_NODE) {
                continue;
            }

            $tag = strtolower($child->nodeName);
            $attributes = [];

            foreach ($child->attributes as $attribute) {
                $attributes[] = $attribute->name;
            }

            foreach ($attributes as $attributeName) {
                $attributeName = strtolower($attributeName);
                $value = trim($child->getAttribute($attributeName));

                if ($tag === 'a' && $attributeName === 'href') {
                    $scheme = strtolower(
                        (string)parse_url($value, PHP_URL_SCHEME)
                    );

                    if (
                        $scheme !== '' &&
                        !in_array($scheme, ['http', 'https', 'mailto'], true)
                    ) {
                        $child->removeAttribute($attributeName);
                    }
                } elseif ($tag === 'a' && $attributeName === 'title') {
                    // Keep the link title.
                } elseif (
                    $tag === 'img' &&
                    in_array($attributeName, ['src', 'alt', 'title', 'width', 'height'], true)
                ) {
                    if ($attributeName === 'src') {
                        $isLocal = preg_match(
                            '#^uploads/[a-zA-Z0-9._-]+$#',
                            $value
                        ) === 1;

                        $isHttps = preg_match('#^https://#i', $value) === 1;

                        if (!$isLocal && !$isHttps) {
                            $child->removeAttribute($attributeName);
                        }
                    } elseif (
                        in_array($attributeName, ['width', 'height'], true) &&
                        !ctype_digit($value)
                    ) {
                        $child->removeAttribute($attributeName);
                    }
                } else {
                    $child->removeAttribute($attributeName);
                }
            }

            $walk($child);
        }
    };

    $walk($root);

    $output = '';

    foreach ($root->childNodes as $child) {
        $output .= $dom->saveHTML($child);
    }

    return $output;
}

function postImageUrl($image): string
{
    $image = trim((string)$image);

    if ($image === '') {
        return '';
    }

    $filename = basename($image);

    if (
        $image !== 'uploads/' . $filename ||
        !is_file(__DIR__ . '/uploads/' . $filename)
    ) {
        return '';
    }

    return 'uploads/' . rawurlencode($filename);
}

// Identify the visitor's role.
$isAdmin = isset($_SESSION['admin_id']);
$isUser = isset($_SESSION['user_id']);

$postId = $_GET['postId'] ?? '';

if (!ctype_digit((string)$postId) || (int)$postId < 1) {
    http_response_code(404);
    exit('Post not found.');
}

$postId = (int)$postId;

// Get the selected post and its author's information.
$query = "
    SELECT
        posts.*,
        users.fullname AS author_fullname,
        users.username AS author_username
    FROM posts
    LEFT JOIN users ON posts.submitted_by = users.id
    WHERE posts.id = ?
    LIMIT 1
";

$stmt = mysqli_prepare($db, $query);
mysqli_stmt_bind_param($stmt, "i", $postId);
mysqli_stmt_execute($stmt);

$result = mysqli_stmt_get_result($stmt);
$post = mysqli_fetch_assoc($result);

mysqli_stmt_close($stmt);

if (!$post) {
    http_response_code(404);
    exit('Post not found.');
}

// Access control:
// Admin can read every post.
// Guest can read Published posts only.
// User can read Published posts and their own Pending/Rejected posts.
$canView = false;

if ($isAdmin) {
    $canView = true;
} elseif ($post['status'] === 'Published') {
    $canView = true;
} elseif (
    $isUser &&
    (int)$post['submitted_by'] === (int)$_SESSION['user_id'] &&
    in_array($post['status'], ['Pending', 'Rejected'], true)
) {
    $canView = true;
}

if (!$canView) {
    http_response_code(404);
    exit('Post not found.');
}

// Display the author's name.
$authorName = 'Administrator';

if (!empty($post['author_fullname'])) {
    $authorName = $post['author_fullname'];
} elseif (!empty($post['author_username'])) {
    $authorName = $post['author_username'];
}

$featuredImageUrl = postImageUrl($post['image'] ?? '');

$statusColors = [
    'Draft' => 'secondary',
    'Pending' => 'warning',
    'Published' => 'success',
    'Rejected' => 'danger',
    'Archived' => 'dark'
];

$statusColor = $statusColors[$post['status']] ?? 'secondary';

$displayName = $isAdmin
    ? ($_SESSION['admin_name'] ?? 'Admin')
    : ($isUser ? ($_SESSION['user_name'] ?? 'User') : 'Guest');

$roleName = $isAdmin ? 'Administrator' : ($isUser ? 'User' : 'Visitor');
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>PostFlow | <?php echo e($post['title']); ?></title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">

    <style>
        .post-detail-card {
            background: #fff;
            border: 1px solid #e8eaf2;
            border-radius: 16px;
            padding: 35px;
            max-width: 1000px;
        }

        .post-detail-title {
            font-size: 30px;
            font-weight: 700;
            line-height: 1.4;
            color: #171a2d;
            overflow-wrap: anywhere;
        }

        .post-meta {
            color: #777d91;
            font-size: 13px;
        }

        .post-featured-image {
            display: block;
            max-width: 100%;
            max-height: 500px;
            height: auto;
            object-fit: contain;
            border-radius: 12px;
            margin: 25px auto;
        }

        .post-full-content {
            font-size: 16px;
            line-height: 1.85;
            color: #343849;
            overflow-wrap: anywhere;
        }

        .post-full-content img {
            max-width: 100%;
            height: auto;
            display: block;
            margin: 18px auto;
            border-radius: 10px;
        }

        .post-full-content a {
            overflow-wrap: anywhere;
        }

        .post-full-content pre {
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            background: #f4f5f9;
            padding: 15px;
            border-radius: 8px;
        }

        .post-full-content blockquote {
            border-left: 4px solid #695cff;
            padding-left: 16px;
            color: #687087;
            margin: 20px 0;
        }

        @media (max-width: 768px) {
            .post-detail-card {
                padding: 20px;
            }

            .post-detail-title {
                font-size: 23px;
            }
        }
    </style>
</head>

<body>

<aside class="sidebar">
    <div class="brand">Post<span>Flow.</span></div>

    <div class="sidebar-label">MAIN MENU</div>

    <a href="index.php">
        <i class="bi bi-grid-1x2-fill"></i>
        Dashboard
    </a>

    <a href="allposts.php" class="active">
        <i class="bi bi-file-earmark-text"></i>
        All Posts
    </a>

    <?php if ($isAdmin || $isUser): ?>
        <a href="post-create.php">
            <i class="bi bi-plus-circle"></i>
            Create Post
        </a>
    <?php endif; ?>

    <?php if (!$isAdmin && !$isUser): ?>
        <a href="login.php">
            <i class="bi bi-box-arrow-in-right"></i>
            Sign In
        </a>
    <?php endif; ?>

    <div class="sidebar-label">PREFERENCES</div>

    <a href="settings.php">
        <i class="bi bi-gear"></i>
        Settings
    </a>
</aside>

<main class="main-content">

    <div class="topbar">
        <div class="page-heading">
            <h2>View Post</h2>
            <p>Read the complete post information.</p>
        </div>

        <div class="profile">
            <div class="text-end d-none d-sm-block">
                <strong style="font-size:13px;"><?php echo e($displayName); ?></strong>
                <p class="mb-0" style="font-size:11px;color:#9295a5;">
                    <?php echo e($roleName); ?>
                </p>
            </div>

            <div class="avatar">
                <?php echo e(strtoupper(substr(trim($displayName), 0, 1))); ?>
            </div>
        </div>
    </div>

    <div class="mb-3">
        <a href="allposts.php" class="btn btn-light">
            <i class="bi bi-arrow-left"></i> Back to All Posts
        </a>
    </div>

    <article class="post-detail-card">

        <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">
            <span class="badge bg-<?php echo e($statusColor); ?>">
                <?php echo e($post['status']); ?>
            </span>

            <span class="post-meta">
                Post #<?php echo (int)$post['id']; ?>
            </span>
        </div>

        <h1 class="post-detail-title">
            <?php echo e($post['title']); ?>
        </h1>

        <div class="post-meta mt-3">
            <i class="bi bi-person-circle"></i>
            <?php echo e($authorName); ?>

            <?php if (!empty($post['created_at'])): ?>
                <span class="mx-2">•</span>
                <i class="bi bi-calendar3"></i>
                <?php echo e(date('F j, Y', strtotime($post['created_at']))); ?>
            <?php endif; ?>
        </div>

        <?php if ($featuredImageUrl !== ''): ?>
            <img
                src="<?php echo e($featuredImageUrl); ?>"
                alt="<?php echo e($post['title']); ?>"
                class="post-featured-image"
            >
        <?php endif; ?>

        <hr class="my-4">

        <div class="post-full-content">
            <?php echo safePostHtml((string)($post['description'] ?? '')); ?>
        </div>

    </article>

</main>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
