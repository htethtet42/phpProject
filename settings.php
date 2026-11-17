
<?php
session_start();
require "connect.php";

$isAdmin = isset($_SESSION['admin_id']);
$isUser = isset($_SESSION['user_id']);

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

$avatarInitial = strtoupper(substr(trim($displayName), 0, 1));
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PostFlow | Settings</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">

    <style>
        .role-card {
            background: #fff;
            border-radius: 12px;
            padding: 25px;
            height: 100%;
            border: 1px solid #eee;
            transition: transform 0.2s ease;
        }

        .role-card:hover {
            transform: translateY(-4px);
        }

        .role-icon {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            margin-bottom: 18px;
        }

        .role-card ul {
            padding-left: 20px;
            margin-bottom: 0;
        }

        .role-card li {
            margin-bottom: 10px;
            color: #666;
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

    <a href="allposts.php">
        <i class="bi bi-file-earmark-text"></i>
        All Posts
    </a>

    <a href="post-create.php">
        <i class="bi bi-plus-circle"></i> Create Post
    </a>

    <div class="sidebar-label">PREFERENCES</div>

    <a href="settings.php" class="active">
        <i class="bi bi-gear"></i>
        Settings
    </a>
</aside>

<!-- Main Content -->
<main class="main-content">

    <div class="topbar">
        <div class="page-heading">
            <h2>Settings</h2>
            <p>Account roles and permissions in PostFlow.</p>
        </div>

        <div class="profile">
            <div class="text-end d-none d-sm-block">
                <strong style="font-size:13px;">
                    <?php echo htmlspecialchars($displayName, ENT_QUOTES, 'UTF-8'); ?>
                </strong>

                <p class="mb-0" style="font-size:11px;color:#9295a5;">
                    <?php echo htmlspecialchars($accountRole, ENT_QUOTES, 'UTF-8'); ?>
                </p>
            </div>

            <div class="avatar">
                <?php echo htmlspecialchars($avatarInitial, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        </div>
    </div>

    <div class="content-card">
        <div class="content-header">
            <div>
                <h5>PostFlow Account Roles</h5>
                <p>Learn about the three account roles and their permissions.</p>
            </div>
        </div>

        <div class="row g-4 p-3">

            <!-- Guest -->
            <div class="col-md-4">
                <div class="role-card">
                    <div class="role-icon bg-secondary-subtle text-secondary">
                        <i class="bi bi-person"></i>
                    </div>

                    <h5>Guest</h5>
                    <span class="badge bg-secondary mb-3">Visitor</span>

                    <p class="text-secondary">
                        Visitors who use PostFlow without registering or logging in.
                    </p>

                    <ul>
                        <li>View published posts.</li>
                        <li>Cannot create posts.</li>
                        <li>Cannot edit or delete posts.</li>
                        <li>Cannot access pending or rejected posts.</li>
                    </ul>
                </div>
            </div>

            <!-- User -->
            <div class="col-md-4">
                <div class="role-card">
                    <div class="role-icon bg-primary-subtle text-primary">
                        <i class="bi bi-person-check"></i>
                    </div>

                    <h5>User</h5>
                    <span class="badge bg-primary mb-3">Registered User</span>

                     <p>
                        Registered users can create posts and submit them
                        for admin approval. They can also view their own
                        pending or rejected posts.
                    </p>

                    <a href="login.php" class="btn btn-primary mt-3">
                        <i class="bi bi-box-arrow-in-right"></i>
                        Sign In as User
                    </a>

                    <ul>
                        <li>View published posts.</li>
                        <li>Create and submit posts.</li>
                        <li>View their own pending and rejected posts.</li>
                        <li>Cannot approve or reject posts.</li>
                        <li>Cannot edit or delete posts.</li>
                    </ul>
                </div>
            </div>

            <!-- Admin -->
            <div class="col-md-4">
                <div class="role-card">
                    <div class="role-icon bg-success-subtle text-success">
                        <i class="bi bi-shield-lock"></i>
                    </div>

                    <h5>Admin</h5>
                    <span class="badge bg-success mb-3">Administrator</span>

                    <p class="text-secondary">
                        Administrators responsible for managing and controlling content.
                    </p>

                    <ul>
                        <li>View all posts.</li>
                        <li>Create and publish posts.</li>
                        <li>Approve or reject submitted posts.</li>
                        <li>Edit and delete posts.</li>
                        <li>Manage content across PostFlow.</li>
                    </ul>
                </div>
            </div>

        </div>
    </div>

</main>

</body>
</html>
