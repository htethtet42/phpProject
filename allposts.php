
<?php
session_start();
require "connect.php";

// Escape plain text safely.
function e($value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

// Sanitize stored rich-text HTML again before displaying it.
function safePostHtml(string $html): string
{
    $allowed = '<p><br><strong><b><em><i><u><s><h1><h2><h3><h4><blockquote><ul><ol><li><a><img><pre><code><hr><sub><sup>';
    $html = strip_tags($html, $allowed);

    if (!class_exists('DOMDocument')) {
        // Fallback keeps allowed formatting tags but removes unsafe link/image attributes.
        $html = preg_replace('/\s+on[a-z]+\s*=\s*("[^"]*"|\\x27[^\\x27]*\\x27|[^\s>]+)/i', '', $html);
        $html = preg_replace('/javascript\s*:/i', '', $html);
        return $html;
    }

    $dom = new DOMDocument('1.0', 'UTF-8');
    $previous = libxml_use_internal_errors(true);
    $dom->loadHTML('<?xml encoding="UTF-8"><div id="post-root">' . $html . '</div>', LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
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
            $attrs = [];
            foreach ($child->attributes as $attr) {
                $attrs[] = $attr->name;
            }

            foreach ($attrs as $attrName) {
                $attrName = strtolower($attrName);
                $value = trim($child->getAttribute($attrName));

                if ($tag === 'a' && $attrName === 'href') {
                    $scheme = strtolower((string)parse_url($value, PHP_URL_SCHEME));
                    if ($scheme !== '' && !in_array($scheme, ['http', 'https', 'mailto'], true)) {
                        $child->removeAttribute($attrName);
                    }
                } elseif ($tag === 'a' && $attrName === 'title') {
                    // Keep link title.
                } elseif ($tag === 'img' && in_array($attrName, ['src', 'alt', 'title', 'width', 'height'], true)) {
                    if ($attrName === 'src') {
                        $isLocal = str_starts_with($value, 'uploads/');
                        $isHttps = preg_match('#^https://#i', $value) === 1;
                        if (!$isLocal && !$isHttps) {
                            $child->removeAttribute($attrName);
                        }
                    } elseif (in_array($attrName, ['width', 'height'], true) && !ctype_digit($value)) {
                        $child->removeAttribute($attrName);
                    }
                } else {
                    $child->removeAttribute($attrName);
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

    // Featured images are expected to be stored under uploads/.
    $filename = basename($image);
    if ($image !== 'uploads/' . $filename || !is_file(__DIR__ . '/uploads/' . $filename)) {
        return '';
    }

    return 'uploads/' . rawurlencode($filename);
}


$isAdmin = isset($_SESSION['admin_id']);
$isUser = isset($_SESSION['user_id']);

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['csrf_token'];

// Determine logged-in account
$isAdmin = isset($_SESSION['admin_id']);
$isUser = isset($_SESSION['user_id']);

$isLoggedIn = $isAdmin || $isUser;

// Get account information
if ($isAdmin) {
    $displayName = $_SESSION['admin_name'] ?? 'Administrator';
    $accountRole = 'Administrator';
} elseif ($isUser) {
    $displayName = $_SESSION['user_name'] ?? 'User';
    $accountRole = 'User';
} else {
    $displayName = 'Guest';
    $accountRole = 'Visitor';
}

// Generate avatar initial
$avatarInitial = strtoupper(
    substr(trim($displayName), 0, 1)
);

// Preserve the post approval/rejection workflow for administrators.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['review_post'])) {
    if (!$isAdmin || !hash_equals($csrfToken, $_POST['csrf_token'] ?? '')) {
        http_response_code(403);
        exit("Access denied.");
    }

    $postId = (int)($_POST['post_id'] ?? 0);
    $decision = $_POST['review_post'];

    if ($postId > 0 && in_array($decision, ['approve', 'reject'], true)) {
        $newStatus = $decision === 'approve' ? 'Published' : 'Rejected';
        $reviewStmt = mysqli_prepare(
            $db,
            "UPDATE posts SET status = ? WHERE id = ? AND status = 'Pending'"
        );
        mysqli_stmt_bind_param($reviewStmt, "si", $newStatus, $postId);

        if (mysqli_stmt_execute($reviewStmt) && mysqli_stmt_affected_rows($reviewStmt) > 0) {
            $_SESSION['successMsg'] = $decision === 'approve'
                ? "Post approved and published successfully."
                : "Post rejected successfully.";
        } else {
            $_SESSION['errorMsg'] = "The post could not be updated. It may no longer be pending.";
        }
        mysqli_stmt_close($reviewStmt);
    }

    header("Location: allposts.php");
    exit();
}

// Only administrators can delete posts
if (isset($_GET['postid_to_delete'])) {

    if (!$isAdmin) {
        http_response_code(403);
        exit("Access denied.");
    }

    $postid_to_delete = (int) $_GET['postid_to_delete'];

    $stmt = mysqli_prepare($db, "DELETE FROM posts WHERE id = ?");

    mysqli_stmt_bind_param($stmt, "i", $postid_to_delete);

    if (mysqli_stmt_execute($stmt)) {
        $_SESSION['successMsg'] = "A post deleted successfully!";
    } else {
        $_SESSION['errorMsg'] = "Error deleting post.";
    }

    mysqli_stmt_close($stmt);

    header("Location: allposts.php");
    exit();
}

// Fetch posts according to account role
if ($isAdmin) {

    // Administrator sees every post
    $query = "SELECT * FROM posts ORDER BY id DESC";
    $posts = mysqli_query($db, $query);

} elseif ($isUser) {

    // Users see published posts and their own submissions
    $query = "SELECT * FROM posts
              WHERE status = 'Published'
              OR (submitted_by = ?
                  AND status IN ('Pending', 'Rejected'))
              ORDER BY id DESC";

    $stmt = mysqli_prepare($db, $query);

    mysqli_stmt_bind_param(
        $stmt,
        "i",
        $_SESSION['user_id']
    );

    mysqli_stmt_execute($stmt);

    $posts = mysqli_stmt_get_result($stmt);

} else {

    // Guests see published posts only
    $query = "SELECT * FROM posts
              WHERE status = 'Published'
              ORDER BY id DESC";

    $posts = mysqli_query($db, $query);
}

if (!$posts) {
    die("Database error: " . mysqli_error($db));
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PostFlow | All Posts</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        .post-featured-thumb {
            width: 72px; height: 54px; object-fit: cover;
            border-radius: 7px; border: 1px solid #e5e7eb;
        }
        .post-content-preview {
            max-width: 360px; max-height: 115px; overflow: hidden;
            line-height: 1.45; overflow-wrap: anywhere;
        }
        .post-content-preview img {
            max-width: 100%; max-height: 80px; height: auto;
            object-fit: contain; border-radius: 5px;
        }
        .post-content-preview p { margin-bottom: .35rem; }
        .post-content-preview h1, .post-content-preview h2,
        .post-content-preview h3, .post-content-preview h4 {
            font-size: 1rem; margin: .25rem 0;
        }
    </style>
</head>
<body>

<!-- Sidebar -->
<aside class="sidebar">
    <div class="brand">
        Post<span>Flow.</span>
    </div>

    <div class="sidebar-label">MAIN MENU</div>

    <a href="index.php">
        <i class="bi bi-grid-1x2-fill"></i>
        Dashboard
    </a>

    <a href="allposts.php" class="active">
        <i class="bi bi-grid-1x2-fill"></i>
        All Posts
    </a>

    <?php if ($isAdmin || $isUser): ?>
        <a href="post-create.php">
            <i class="bi bi-plus-circle"></i>
            Create Post
        </a>
    <?php endif; ?>

    <?php if (!isset($_SESSION['admin_id']) && !isset($_SESSION['user_id'])): ?>
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

<!-- Main Content -->
<main class="main-content">

    <!-- Page Heading -->
    <div class="topbar">
        <div class="page-heading">
            <h2>All Posts</h2>
            <p>Manage, edit and organize all your posts.</p>
        </div>

        <!-- Profile -->
        <div class="profile">
            <div class="text-end d-none d-sm-block">
                <strong style="font-size:13px;">
                    <?php echo htmlspecialchars($displayName, ENT_QUOTES, 'UTF-8'); ?>
                </strong>
                <p class="mb-0" style="font-size:11px;color:#9295a5;">
                    <?php echo htmlspecialchars($accountRole, ENT_QUOTES, 'UTF-8'); ?>
                </p>
            </div>

            <div class="profile-dropdown">
                <button
                    type="button"
                    class="avatar"
                    id="profileButton"
                    aria-label="Open profile menu"
                    aria-expanded="false">
                    <?php echo htmlspecialchars($avatarInitial, ENT_QUOTES, 'UTF-8'); ?>
                </button>

                <div class="profile-menu" id="profileMenu">
                    <div class="profile-menu-header">
                        <strong>
                            <?php echo htmlspecialchars($displayName, ENT_QUOTES, 'UTF-8'); ?>
                        </strong>
                        <small>
                            <?php echo htmlspecialchars($accountRole, ENT_QUOTES, 'UTF-8'); ?>
                        </small>
                    </div>

                    <div class="profile-menu-divider"></div>

                    <?php if ($isLoggedIn): ?>
                        <a href="logout.php" class="profile-menu-item logout-item">
                            <i class="bi bi-box-arrow-right"></i>
                            Log Out
                        </a>
                    <?php else: ?>
                        <a href="login.php" class="profile-menu-item">
                            <i class="bi bi-box-arrow-in-right"></i>
                            Sign In
                        </a>
                    <?php endif; ?>

                    <button
                        type="button"
                        class="profile-menu-item cancel-item"
                        id="cancelProfileMenu">
                        <i class="bi bi-x-circle"></i>
                        Cancel
                    </button>
                </div>
            </div>
        </div>
    </div>
    <!-- Error Message -->
    <?php if (isset($_SESSION['errorMsg'])): ?>
        <div class="alert alert-danger alert-dismissible fade show">
            <?php
                echo e($_SESSION['errorMsg']);
                unset($_SESSION['errorMsg']);
            ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <!-- Success Message -->
    <?php if (isset($_SESSION['successMsg'])): ?>
        <div class="alert alert-success alert-dismissible fade show">
            <?php
                echo htmlspecialchars($_SESSION['successMsg'], ENT_QUOTES, 'UTF-8');
                unset($_SESSION['successMsg']);
            ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <!-- Posts Table -->
    <div class="content-card">
        <div class="content-header">
            <div>
                <h5>Posts Management</h5>
                <p>View and manage all your content</p>
            </div>

            <?php if ($isAdmin || $isUser): ?>
                <a href="post-create.php" class="btn-primary-custom">
                    <i class="bi bi-plus-lg"></i>
                    Add New Post
                </a>
            <?php else: ?>
                <a href="login.php" class="btn-primary-custom">
                    <i class="bi bi-box-arrow-in-right"></i>
                    Sign In to Create Post
                </a>
            <?php endif; ?>
        </div>

        <div class="table-wrapper">
            <table class="custom-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Image</th>
                        <th>Post Title</th>
                        <th>Content Preview</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (mysqli_num_rows($posts) > 0): ?>
                        <?php while ($post = mysqli_fetch_assoc($posts)): ?>
                            <tr>
                                <td>
                                    <span class="post-id">
                                        #<?php echo (int)$post['id']; ?>
                                    </span>
                                </td>
                                <td>
                                    <?php $featuredImageUrl = postImageUrl($post['image'] ?? ''); ?>
                                    <?php if ($featuredImageUrl !== ''): ?>
                                        <img src="<?php echo e($featuredImageUrl); ?>"
                                             alt="Featured image"
                                             class="post-featured-thumb">
                                    <?php else: ?>
                                        <span class="text-secondary small">No image</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="post-title">
                                        <?php echo e($post['title']); ?>
                                    </span>
                                </td>
                                <td>
                                    <div class="post-content-preview">
                                        <?php echo safePostHtml($post['description'] ?? ''); ?>
                                    </div>
                                </td>
                                <td>
                                    <?php
                                    $status = $post['status'];

                                    $badgeClass = [
                                        'Draft' => 'secondary',
                                        'Pending' => 'warning',
                                        'Published' => 'success',
                                        'Rejected' => 'danger',
                                        'Archived' => 'dark'
                                    ];

                                    $color = $badgeClass[$status] ?? 'secondary';
                                    ?>

                                    <span class="badge bg-<?php echo $color; ?>">
                                        <?php echo htmlspecialchars($status, ENT_QUOTES, 'UTF-8'); ?>
                                    </span>
                                </td>
                                <td>                                    
                                    <div class="action-buttons">
                                        <!-- Everyone can view posts already permitted by the PHP query -->
                                        <a href="view-post.php?postId=<?php echo (int)$post['id']; ?>"
                                        class="btn btn-sm btn-outline-primary">
                                            <i class="bi bi-eye"></i> View
                                        </a>

                                        <?php if ($isAdmin): ?>

                                            <?php if (($post['status'] ?? '') === 'Pending'): ?>
                                                <form method="POST" class="d-inline">
                                                    <input type="hidden" name="csrf_token"
                                                        value="<?php echo e($csrfToken); ?>">

                                                    <input type="hidden" name="post_id"
                                                        value="<?php echo (int)$post['id']; ?>">

                                                    <button type="submit" name="review_post"
                                                            value="approve" class="btn btn-sm btn-success">
                                                        <i class="bi bi-check-circle"></i> Approve
                                                    </button>

                                                    <button type="submit" name="review_post"
                                                            value="reject" class="btn btn-sm btn-danger"
                                                            onclick="return confirm('Are you sure you want to reject this post?');">
                                                        <i class="bi bi-x-circle"></i> Reject
                                                    </button>
                                                </form>
                                            <?php endif; ?>

                                            <a href="post-edit.php?postId=<?php echo (int)$post['id']; ?>"
                                            class="btn-edit">
                                                <i class="bi bi-pencil-square"></i> Edit
                                            </a>

                                            <a href="allposts.php?postid_to_delete=<?php echo (int)$post['id']; ?>"
                                            class="btn-delete"
                                            onclick="return confirm('Are you sure you want to delete this post?');">
                                                <i class="bi bi-trash3"></i> Delete
                                            </a>

                                        <?php elseif ($isUser): ?>

                                            <?php
                                            $canEdit = (int)$post['submitted_by'] === (int)$_SESSION['user_id']
                                                    && $post['status'] === 'Pending';
                                            ?>

                                            <?php if ($canEdit): ?>
                                                <a href="post-edit.php?postId=<?php echo (int)$post['id']; ?>"
                                                class="btn-edit">
                                                    <i class="bi bi-pencil-square"></i> Edit
                                                </a>
                                            <?php endif; ?>

                                        <?php endif; ?>

                                    </div>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="6" class="text-center py-5">
                                <i class="bi bi-inbox fs-1 text-secondary"></i>
                                <p class="mt-3 text-secondary">No posts found yet.</p>
                                <?php if (isset($_SESSION['admin_id'])): ?>
                                    <a href="post-create.php" class="btn-primary-custom">
                                        Create Your First Post
                                    </a>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</main>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
const profileButton = document.getElementById("profileButton");
const profileMenu = document.getElementById("profileMenu");
const cancelProfileMenu = document.getElementById("cancelProfileMenu");

profileButton.addEventListener("click", function (event) {
    event.stopPropagation();
    profileMenu.classList.toggle("show");
    const isOpen = profileMenu.classList.contains("show");
    profileButton.setAttribute("aria-expanded", isOpen);
});

cancelProfileMenu.addEventListener("click", function () {
    profileMenu.classList.remove("show");
    profileButton.setAttribute("aria-expanded", "false");
});

document.addEventListener("click", function (event) {
    if (!event.target.closest(".profile-dropdown")) {
        profileMenu.classList.remove("show");
        profileButton.setAttribute("aria-expanded", "false");
    }
});

document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
        profileMenu.classList.remove("show");
        profileButton.setAttribute("aria-expanded", "false");
    }
});
</script>

</body>
</html>