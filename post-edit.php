<?php
session_start();
require "connect.php";

// 1. AUTHENTICATION

$isAdmin = isset($_SESSION['admin_id']);
$isUser  = isset($_SESSION['user_id']);

if (!$isAdmin && !$isUser) {
    header("Location: login.php");
    exit();
}

// 2. CSRF TOKEN

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$csrfToken = $_SESSION['csrf_token'];

function e($value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

// --------------------------------------------------
// 3. VALIDATE POST ID
// --------------------------------------------------

$post_id = $_GET['postId'] ?? $_POST['postId'] ?? '';

if (!ctype_digit((string)$post_id) || (int)$post_id < 1) {
    die("Invalid post ID!");
}

$post_id = (int)$post_id;

// --------------------------------------------------
// 4. LOAD SELECTED POST
// --------------------------------------------------

$stmt = $db->prepare("SELECT * FROM posts WHERE id = ?");

$stmt->bind_param("i", $post_id);
$stmt->execute();

$result = $stmt->get_result();
$post = $result->fetch_assoc();

$stmt->close();

if (!$post) {
    die("Post not found!");
}

// --------------------------------------------------
// 5. CHECK EDIT PERMISSIONS
// --------------------------------------------------

if (!$isAdmin) {

    if (
        !$isUser ||
        (int)$post['submitted_by'] !== (int)$_SESSION['user_id'] ||
        $post['status'] !== 'Pending'
    ) {
        http_response_code(403);
        die("You are not allowed to edit this post.");
    }
}

// --------------------------------------------------
// 6. HTML SANITIZER
// --------------------------------------------------

function cleanRichHtml(string $html): string
{
    $allowedTags = [
        'p', 'br', 'strong', 'b', 'em', 'i', 'u', 's',
        'h1', 'h2', 'h3', 'h4', 'blockquote',
        'ul', 'ol', 'li', 'a', 'img', 'pre', 'code',
        'hr', 'sub', 'sup'
    ];

    if (!class_exists('DOMDocument')) {
        return nl2br(e(strip_tags($html)));
    }

    $dom = new DOMDocument('1.0', 'UTF-8');

    $previous = libxml_use_internal_errors(true);

    $dom->loadHTML(
        '<?xml encoding="UTF-8"><div id="editor-root">' . $html . '</div>',
        LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD
    );

    libxml_clear_errors();
    libxml_use_internal_errors($previous);

    $root = null;

    foreach ($dom->getElementsByTagName('div') as $candidate) {
        if ($candidate->getAttribute('id') === 'editor-root') {
            $root = $candidate;
            break;
        }
    }

    if (!$root) {
        return '';
    }

    $cleanNode = function ($node) use (&$cleanNode, $allowedTags, $dom) {

        $children = [];

        foreach ($node->childNodes as $child) {
            $children[] = $child;
        }

        foreach ($children as $child) {

            if ($child->nodeType === XML_ELEMENT_NODE) {

                $tag = strtolower($child->nodeName);

                if (!in_array($tag, $allowedTags, true)) {

                    if (in_array($tag, [
                        'script', 'style', 'iframe',
                        'object', 'embed', 'form'
                    ], true)) {
                        $node->removeChild($child);
                    } else {
                        while ($child->firstChild) {
                            $node->insertBefore($child->firstChild, $child);
                        }

                        $node->removeChild($child);
                    }

                    continue;
                }

                $attributes = [];

                foreach ($child->attributes as $attribute) {
                    $attributes[] = $attribute->name;
                }

                foreach ($attributes as $attributeName) {

                    $attributeName = strtolower($attributeName);
                    $value = $child->getAttribute($attributeName);

                    // Links
                    if ($tag === 'a' && $attributeName === 'href') {

                        $scheme = strtolower(
                            (string)parse_url(trim($value), PHP_URL_SCHEME)
                        );

                        if (
                            $scheme !== '' &&
                            !in_array($scheme, ['http', 'https', 'mailto'], true)
                        ) {
                            $child->removeAttribute($attributeName);
                        }

                    // Link title
                    } elseif ($tag === 'a' && $attributeName === 'title') {

                        // Keep link title.

                    // Images
                    } elseif (
                        $tag === 'img' &&
                        in_array($attributeName, [
                            'src', 'alt', 'title', 'width', 'height'
                        ], true)
                    ) {

                        if ($attributeName === 'src') {

                            $safeLocal = preg_match(
                                '#^uploads/[A-Za-z0-9._-]+\.(jpg|jpeg|png|gif|webp)$#i',
                                $value
                            ) === 1;

                            $safeRemote = preg_match(
                                '#^https://#i',
                                $value
                            ) === 1;

                            if (!$safeLocal && !$safeRemote) {
                                $child->removeAttribute($attributeName);
                            }

                        } elseif (
                            in_array($attributeName, ['width', 'height'], true) &&
                            !ctype_digit($value)
                        ) {
                            $child->removeAttribute($attributeName);
                        }

                    // Quill alignment classes
                    } elseif (
                        $attributeName === 'class' &&
                        in_array($tag, ['p', 'h1', 'h2', 'h3', 'h4', 'blockquote'], true)
                    ) {

                        $classes = preg_split('/\s+/', trim($value));

                        $safeClasses = [];

                        foreach ($classes as $class) {
                            if (preg_match(
                                '/^(ql-align-(center|right|justify)|ql-indent-[1-8])$/',
                                $class
                            )) {
                                $safeClasses[] = $class;
                            }
                        }

                        if ($safeClasses) {
                            $child->setAttribute(
                                'class',
                                implode(' ', $safeClasses)
                            );
                        } else {
                            $child->removeAttribute('class');
                        }

                    } else {
                        $child->removeAttribute($attributeName);
                    }
                }

                $cleanNode($child);

            } elseif ($child->nodeType !== XML_TEXT_NODE) {
                $node->removeChild($child);
            }
        }
    };

    $cleanNode($root);

    $result = '';

    foreach ($root->childNodes as $child) {
        $result .= $dom->saveHTML($child);
    }

    libxml_clear_errors();
    libxml_use_internal_errors($previous);

    return $result;
}

// --------------------------------------------------
// 7. MEDIA FILES
// --------------------------------------------------

function mediaFiles(): array
{
    $directory = __DIR__ . '/uploads';

    if (!is_dir($directory)) {
        return [];
    }

    $files = [];

    foreach (scandir($directory) ?: [] as $file) {

        if ($file === '.' || $file === '..') {
            continue;
        }

        $path = $directory . DIRECTORY_SEPARATOR . $file;

        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));

        if (
            is_file($path) &&
            in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'], true)
        ) {
            $files[] = 'uploads/' . $file;
        }
    }

    rsort($files);

    return $files;
}

// --------------------------------------------------
// 8. INITIAL FORM VALUES
// --------------------------------------------------

$title = $post['title'];
$desc = $post['description'];
$featuredImage = $post['image'] ?? '';

$titleError = '';
$descError = '';
$error = '';

// --------------------------------------------------
// 9. IMAGE UPLOAD ENDPOINT
// --------------------------------------------------

if (
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    ($_POST['action'] ?? '') === 'upload_media'
) {

    header('Content-Type: application/json; charset=utf-8');

    if (!hash_equals($csrfToken, $_POST['csrf_token'] ?? '')) {

        http_response_code(403);

        echo json_encode([
            'success' => false,
            'message' => 'Security token expired. Refresh the page.'
        ]);

        exit();
    }

    if (
        !isset($_FILES['media_file']) ||
        $_FILES['media_file']['error'] !== UPLOAD_ERR_OK
    ) {

        http_response_code(400);

        echo json_encode([
            'success' => false,
            'message' => 'Please choose an image to upload.'
        ]);

        exit();
    }

    $file = $_FILES['media_file'];

    if ($file['size'] > 5 * 1024 * 1024) {

        http_response_code(400);

        echo json_encode([
            'success' => false,
            'message' => 'Image must be 5 MB or smaller.'
        ]);

        exit();
    }

    $imageInfo = @getimagesize($file['tmp_name']);
    $mime = $imageInfo['mime'] ?? '';

    $allowedMime = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/gif'  => 'gif',
        'image/webp' => 'webp'
    ];

    if (!isset($allowedMime[$mime])) {

        http_response_code(400);

        echo json_encode([
            'success' => false,
            'message' => 'Only JPG, PNG, GIF and WEBP are allowed.'
        ]);

        exit();
    }

    $uploadDirectory = __DIR__ . '/uploads';

    if (
        !is_dir($uploadDirectory) &&
        !mkdir($uploadDirectory, 0755, true)
    ) {

        http_response_code(500);

        echo json_encode([
            'success' => false,
            'message' => 'Could not create uploads folder.'
        ]);

        exit();
    }

    $newName = bin2hex(random_bytes(16)) . '.' . $allowedMime[$mime];

    $destination = $uploadDirectory . DIRECTORY_SEPARATOR . $newName;

    if (!move_uploaded_file($file['tmp_name'], $destination)) {

        http_response_code(500);

        echo json_encode([
            'success' => false,
            'message' => 'Image upload failed. Check folder permissions.'
        ]);

        exit();
    }

    echo json_encode([
        'success' => true,
        'url' => 'uploads/' . $newName
    ]);

    exit();
}

// --------------------------------------------------
// 10. UPDATE POST
// --------------------------------------------------

if (
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    isset($_POST['update_post_button'])
) {

    if (!hash_equals($csrfToken, $_POST['csrf_token'] ?? '')) {

        $error = 'Your session token expired. Refresh the page and try again.';

    } else {

        $title = trim($_POST['title'] ?? '');

        $rawDescription = trim($_POST['description'] ?? '');

        $desc = cleanRichHtml($rawDescription);

        $featuredImage = trim($_POST['featured_image'] ?? '');

        // Validate title
        if ($title === '') {

            $titleError = 'The title field is required.';

        } elseif (mb_strlen($title) > 100) {

            $titleError = 'The title must be 100 characters or fewer.';

        }

        // Validate description
        $plainDescription = trim(
            html_entity_decode(
                strip_tags($desc),
                ENT_QUOTES | ENT_HTML5,
                'UTF-8'
            )
        );

        if ($plainDescription === '') {
            $descError = 'The description field is required.';
        }

        // Validate featured image
        if ($featuredImage !== '') {

            $safeImage = basename($featuredImage);

            $featuredPath = __DIR__ . '/uploads/' . $safeImage;

            if (
                $featuredImage !== 'uploads/' . $safeImage ||
                !is_file($featuredPath) ||
                !in_array(
                    strtolower(pathinfo($safeImage, PATHINFO_EXTENSION)),
                    ['jpg', 'jpeg', 'png', 'gif', 'webp'],
                    true
                )
            ) {
                $error = 'Please choose a valid featured image.';
            }
        }

        // Save changes
        if (
            $titleError === '' &&
            $descError === '' &&
            $error === ''
        ) {

            if ($isAdmin) {

                // Admin can edit any post.
                $query = "
                    UPDATE posts
                    SET title = ?, description = ?, image = ?
                    WHERE id = ?
                ";

                $stmt = $db->prepare($query);

                $stmt->bind_param(
                    "sssi",
                    $title,
                    $desc,
                    $featuredImage,
                    $post_id
                );

            } else {

                // Normal user can edit only their own Pending post.
                $userId = (int)$_SESSION['user_id'];

                $query = "
                    UPDATE posts
                    SET title = ?, description = ?, image = ?
                    WHERE id = ?
                    AND submitted_by = ?
                    AND status = 'Pending'
                ";

                $stmt = $db->prepare($query);

                $stmt->bind_param(
                    "sssii",
                    $title,
                    $desc,
                    $featuredImage,
                    $post_id,
                    $userId
                );
            }

            if ($stmt->execute()) {

                if (!$isAdmin && $stmt->affected_rows === 0) {

                    $stmt->close();

                    $error = 'The post could not be updated. Check its status and permissions.';

                } else {

                    $stmt->close();

                    $_SESSION['successMsg'] = 'Post updated successfully!';

                    header('Location: allposts.php');
                    exit();
                }

            } else {

                $error = 'Update error: ' . $stmt->error;

                $stmt->close();
            }
        }
    }
}

// --------------------------------------------------
// 11. LOAD MEDIA FILES
// --------------------------------------------------

$existingMedia = mediaFiles();

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>PostFlow | Edit Post</title>

    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css"
        rel="stylesheet"
    >

    <link rel="stylesheet" href="css/style.css">

    <link
        rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"
    >

    <link
        href="https://cdn.jsdelivr.net/npm/quill@2.0.3/dist/quill.snow.css"
        rel="stylesheet"
    >

    <style>
        .editor-shell {
            background: #fff;
            border: 1px solid #dee2e6;
            border-radius: 10px;
            overflow: hidden;
        }

        #editor {
            min-height: 260px;
            color: #212529;
        }

        #editor .ql-editor {
            min-height: 260px;
            font-size: 15px;
        }

        .media-toolbar {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        }

        .media-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(125px, 1fr));
            gap: 12px;
            max-height: 430px;
            overflow-y: auto;
        }

        .media-item {
            border: 1px solid #dee2e6;
            border-radius: 9px;
            padding: 8px;
            background: #fff;
        }

        .media-item img {
            width: 100%;
            height: 100px;
            object-fit: cover;
            border-radius: 6px;
        }

        .media-item .btn {
            width: 100%;
            margin-top: 6px;
            font-size: 12px;
        }

        .featured-preview {
            display: none;
            max-width: 220px;
            max-height: 150px;
            object-fit: cover;
            border-radius: 8px;
            margin-top: 10px;
        }

        .ql-toolbar.ql-snow {
            border: 0;
            border-bottom: 1px solid #dee2e6;
        }

        .ql-container.ql-snow {
            border: 0;
        }
    </style>

</head>

<body>

<!-- SIDEBAR -->

<aside class="sidebar">

    <div class="brand">Post<span>Flow.</span></div>

    <div class="sidebar-label">MAIN MENU</div>

    <a href="index.php">
        <i class="bi bi-grid-1x2-fill"></i> Dashboard
    </a>

    <a href="allposts.php" class="active">
        <i class="bi bi-file-earmark-text"></i> All Posts
    </a>

    <a href="post-create.php">
        <i class="bi bi-plus-circle"></i> Create Post
    </a>

    <div class="sidebar-label">PREFERENCES</div>

    <a href="settings.php">
        <i class="bi bi-gear"></i> Settings
    </a>

</aside>


<!-- MAIN CONTENT -->

<main class="main-content">

    <div class="topbar">

        <div class="page-heading">

            <h2>Edit Post</h2>

            <p>Update your existing post information.</p>

        </div>

        <a href="allposts.php" class="btn btn-light">
            <i class="bi bi-arrow-left"></i> Back
        </a>

    </div>

    <?php if ($error !== ''): ?>

        <div class="alert alert-danger">
            <?= e($error) ?>
        </div>

    <?php endif; ?>


    <div class="form-card">

        <div class="mb-4">

            <h5 class="fw-bold">Edit Post Information</h5>

            <p class="text-secondary small">
                Make changes to your title, format your content, and manage images.
            </p>

        </div>


        <!-- EDIT FORM -->

        <form
            method="POST"
            id="postForm"
            action="post-edit.php?postId=<?= $post_id ?>"
        >

            <input
                type="hidden"
                name="postId"
                value="<?= $post_id ?>"
            >

            <input
                type="hidden"
                name="csrf_token"
                value="<?= e($csrfToken) ?>"
            >

            <input
                type="hidden"
                name="description"
                id="descriptionInput"
            >

            <input
                type="hidden"
                name="featured_image"
                id="featuredImageInput"
                value="<?= e($featuredImage) ?>"
            >


            <!-- POST TITLE -->

            <div class="form-group mb-4">

                <label for="postTitle" class="form-label">
                    Post Title
                </label>

                <input
                    type="text"
                    id="postTitle"
                    name="title"
                    maxlength="100"
                    class="form-control <?= $titleError !== '' ? 'is-invalid' : '' ?>"
                    placeholder="Enter post title..."
                    value="<?= e($title) ?>"
                    required
                >

                <?php if ($titleError !== ''): ?>

                    <div class="invalid-feedback">
                        <?= e($titleError) ?>
                    </div>

                <?php endif; ?>

            </div>


            <!-- RICH TEXT EDITOR -->

            <div class="form-group mb-4">

                <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-2">

                    <label class="form-label mb-0">
                        Post Content
                    </label>

                    <button
                        type="button"
                        class="btn btn-outline-primary btn-sm"
                        data-bs-toggle="modal"
                        data-bs-target="#mediaModal"
                    >
                        <i class="bi bi-images"></i>
                        Open Media Manager
                    </button>

                </div>

                <div class="editor-shell">

                    <div id="editor"></div>

                </div>

                <?php if ($descError !== ''): ?>

                    <div class="text-danger small mt-2">
                        <?= e($descError) ?>
                    </div>

                <?php endif; ?>

                <div class="form-text">
                    Use the toolbar to format text. Use Media Manager to upload or insert images.
                </div>

            </div>


            <!-- FEATURED IMAGE -->

            <div class="form-group mb-4">

                <label class="form-label">
                    Featured Image
                    <span class="text-secondary">(optional)</span>
                </label>

                <div class="media-toolbar">

                    <button
                        type="button"
                        class="btn btn-outline-secondary"
                        data-bs-toggle="modal"
                        data-bs-target="#mediaModal"
                    >
                        <i class="bi bi-image"></i>
                        Choose from Media
                    </button>

                    <button
                        type="button"
                        class="btn btn-outline-danger btn-sm"
                        id="removeFeaturedImage"
                        style="display:none;"
                    >
                        Remove image
                    </button>

                </div>

                <img
                    id="featuredPreview"
                    class="featured-preview"
                    alt="Featured image preview"
                >

            </div>


            <!-- FORM ACTIONS -->

            <div class="form-actions">

                <button
                    type="submit"
                    name="update_post_button"
                    value="1"
                    class="btn-primary-custom"
                >
                    <i class="bi bi-check-lg"></i>
                    Save Changes
                </button>

                <a href="allposts.php" class="btn btn-light px-4">
                    Cancel
                </a>

            </div>

        </form>

    </div>

</main>


<!-- MEDIA MANAGER -->

<div
    class="modal fade"
    id="mediaModal"
    tabindex="-1"
    aria-labelledby="mediaModalLabel"
    aria-hidden="true"
>

    <div class="modal-dialog modal-xl modal-dialog-scrollable">

        <div class="modal-content">

            <div class="modal-header">

                <h5 class="modal-title" id="mediaModalLabel">
                    <i class="bi bi-images"></i>
                    Media Manager
                </h5>

                <button
                    type="button"
                    class="btn-close"
                    data-bs-dismiss="modal"
                    aria-label="Close"
                ></button>

            </div>

            <div class="modal-body">

                <div class="media-toolbar mb-3">

                    <input
                        type="search"
                        id="mediaSearch"
                        class="form-control"
                        style="max-width:320px;"
                        placeholder="Search images by filename..."
                    >

                    <label class="btn btn-primary mb-0">

                        <i class="bi bi-cloud-arrow-up"></i>
                        Upload Image

                        <input
                            type="file"
                            id="mediaUpload"
                            accept="image/jpeg,image/png,image/gif,image/webp"
                            hidden
                        >

                    </label>

                    <span class="text-secondary small">
                        JPG, PNG, GIF or WEBP · Maximum 5 MB
                    </span>

                </div>

                <div
                    id="uploadMessage"
                    class="small mb-3"
                    role="status"
                ></div>


                <!-- IMAGE GRID -->

                <div class="media-grid" id="mediaGrid">

                    <?php foreach ($existingMedia as $media): ?>

                        <div
                            class="media-item"
                            data-filename="<?= e(strtolower(basename($media))) ?>"
                        >

                            <img
                                src="<?= e($media) ?>"
                                alt="<?= e(basename($media)) ?>"
                            >

                            <div
                                class="small text-truncate mt-1"
                                title="<?= e(basename($media)) ?>"
                            >
                                <?= e(basename($media)) ?>
                            </div>

                            <button
                                type="button"
                                class="btn btn-outline-primary btn-sm insert-media"
                                data-url="<?= e($media) ?>"
                            >
                                Insert in content
                            </button>

                            <button
                                type="button"
                                class="btn btn-outline-secondary btn-sm choose-featured"
                                data-url="<?= e($media) ?>"
                            >
                                Set as featured
                            </button>

                        </div>

                    <?php endforeach; ?>

                </div>

                <div
                    id="noMediaMessage"
                    class="text-secondary text-center py-4"
                    style="<?= count($existingMedia) ? 'display:none;' : '' ?>"
                >
                    No images found. Upload an image to get started.
                </div>

            </div>

        </div>

    </div>

</div>


<!-- JAVASCRIPT -->

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>

<script src="https://cdn.jsdelivr.net/npm/quill@2.0.3/dist/quill.js"></script>

<script>

    // ==========================================
    // 1. INITIALIZE QUILL
    // ==========================================

    const csrfToken = <?= json_encode($csrfToken) ?>;

    const initialContent = <?= json_encode(
        $desc,
        JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT
    ) ?>;

    const quill = new Quill('#editor', {

        theme: 'snow',

        placeholder: 'Write your post here...',

        modules: {

            toolbar: [

                [{ header: [1, 2, 3, false] }],

                ['bold', 'italic', 'underline', 'strike'],

                [{ list: 'ordered' }, { list: 'bullet' }],

                ['blockquote', 'code-block'],

                [{ script: 'sub' }, { script: 'super' }],

                [{ align: [] }],

                ['link', 'clean']

            ]

        }

    });


    // Load existing post content

    if (initialContent) {
        quill.root.innerHTML = initialContent;
    }


    // ==========================================
    // 2. MEDIA MANAGER ELEMENTS
    // ==========================================

    const mediaGrid = document.getElementById('mediaGrid');

    const mediaSearch = document.getElementById('mediaSearch');

    const uploadMessage = document.getElementById('uploadMessage');

    const mediaUpload = document.getElementById('mediaUpload');

    const featuredInput = document.getElementById('featuredImageInput');

    const featuredPreview = document.getElementById('featuredPreview');

    const removeFeaturedButton = document.getElementById('removeFeaturedImage');


    // ==========================================
    // 3. FEATURED IMAGE
    // ==========================================

    function setFeaturedImage(url) {

        featuredInput.value = url;

        featuredPreview.src = url;

        featuredPreview.style.display = 'block';

        removeFeaturedButton.style.display = 'inline-block';

    }


    // Show existing featured image

    if (featuredInput.value) {
        setFeaturedImage(featuredInput.value);
    }


    // Remove featured image

    removeFeaturedButton.addEventListener('click', () => {

        featuredInput.value = '';

        featuredPreview.removeAttribute('src');

        featuredPreview.style.display = 'none';

        removeFeaturedButton.style.display = 'none';

    });


    // ==========================================
    // 4. ADD NEW MEDIA CARD
    // ==========================================

    function addMediaCard(url) {

        const filename = url.split('/').pop();

        const card = document.createElement('div');

        card.className = 'media-item';

        card.dataset.filename = filename.toLowerCase();


        const image = document.createElement('img');

        image.src = url;

        image.alt = filename;


        const name = document.createElement('div');

        name.className = 'small text-truncate mt-1';

        name.textContent = filename;


        const insertButton = document.createElement('button');

        insertButton.type = 'button';

        insertButton.className = 'btn btn-outline-primary btn-sm insert-media';

        insertButton.dataset.url = url;

        insertButton.textContent = 'Insert in content';


        const featuredButton = document.createElement('button');

        featuredButton.type = 'button';

        featuredButton.className = 'btn btn-outline-secondary btn-sm choose-featured';

        featuredButton.dataset.url = url;

        featuredButton.textContent = 'Set as featured';


        card.append(image, name, insertButton, featuredButton);

        mediaGrid.prepend(card);

        document.getElementById('noMediaMessage').style.display = 'none';

    }


    // ==========================================
    // 5. INSERT OR SELECT MEDIA
    // ==========================================

    mediaGrid.addEventListener('click', (event) => {

        const insertButton = event.target.closest('.insert-media');

        const featuredButton = event.target.closest('.choose-featured');


        if (insertButton) {

            const url = insertButton.dataset.url;

            const range = quill.getSelection(true);

            quill.insertEmbed(range.index, 'image', url, 'user');

            quill.setSelection(range.index + 1, 0);

            bootstrap.Modal
                .getInstance(document.getElementById('mediaModal'))
                .hide();

        }


        if (featuredButton) {

            setFeaturedImage(featuredButton.dataset.url);

            bootstrap.Modal
                .getInstance(document.getElementById('mediaModal'))
                .hide();

        }

    });


    // ==========================================
    // 6. SEARCH MEDIA
    // ==========================================

    mediaSearch.addEventListener('input', () => {

        const term = mediaSearch.value.trim().toLowerCase();

        let visibleCount = 0;


        mediaGrid.querySelectorAll('.media-item').forEach((card) => {

            const matches = card.dataset.filename.includes(term);

            card.style.display = matches ? '' : 'none';

            if (matches) {
                visibleCount++;
            }

        });


        const noMediaMessage = document.getElementById('noMediaMessage');

        noMediaMessage.style.display = visibleCount ? 'none' : 'block';

        noMediaMessage.textContent = visibleCount
            ? 'No images found. Upload an image to get started.'
            : 'No matching images found.';

    });


    // ==========================================
    // 7. UPLOAD IMAGE
    // ==========================================

    mediaUpload.addEventListener('change', async () => {

        const file = mediaUpload.files[0];

        if (!file) return;


        uploadMessage.className = 'small mb-3 text-secondary';

        uploadMessage.textContent = 'Uploading image...';


        const formData = new FormData();

        formData.append('action', 'upload_media');

        formData.append('csrf_token', csrfToken);

        formData.append('media_file', file);


        try {

            const response = await fetch(
                'post-edit.php?postId=<?= $post_id ?>',
                {
                    method: 'POST',
                    body: formData
                }
            );


            const result = await response.json();


            if (!response.ok || !result.success) {

                throw new Error(result.message || 'Upload failed.');

            }


            addMediaCard(result.url);


            uploadMessage.className = 'small mb-3 text-success';

            uploadMessage.textContent = 'Image uploaded successfully.';


        } catch (error) {

            uploadMessage.className = 'small mb-3 text-danger';

            uploadMessage.textContent = error.message;

        } finally {

            mediaUpload.value = '';

        }

    });


    // ==========================================
    // 8. SUBMIT FORM
    // ==========================================

    document.getElementById('postForm').addEventListener(
        'submit',
        (event) => {

            const html = quill.root.innerHTML;

            const plainText = quill.getText().trim();


            if (!plainText) {

                event.preventDefault();

                alert('Please enter your post content.');

                return;

            }


            document.getElementById('descriptionInput').value = html;

        }
    );

</script>

</body>
</html>
