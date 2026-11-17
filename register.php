
<?php
session_start();
require "connect.php";

// Redirect already logged-in accounts
if (isset($_SESSION['admin_id']) || isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit();
}

$error = "";
$success = "";

$username = "";
$fullname = "";
$email = "";

// Generate CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Handle Registration
if ($_SERVER['REQUEST_METHOD'] === 'POST' &&
    isset($_POST['register'])) {

    $username = trim($_POST['username'] ?? '');
    $fullname = trim($_POST['fullname'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $csrfToken = $_POST['csrf_token'] ?? '';

    if (!hash_equals($_SESSION['csrf_token'], $csrfToken)) {

        $error = "Invalid request. Please refresh the page.";

    } elseif (
        $username === '' ||
        $fullname === '' ||
        $email === '' ||
        $password === '' ||
        $confirmPassword === ''
    ) {

        $error = "Please complete all fields.";

    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        $error = "Please enter a valid email address.";

    } elseif (!preg_match('/^[a-zA-Z0-9_]{3,100}$/', $username)) {

        $error = "Username must contain 3-100 letters, numbers or underscores.";

    } elseif (strlen($password) < 8) {

        $error = "Password must contain at least 8 characters.";

    } elseif ($password !== $confirmPassword) {

        $error = "Passwords do not match.";

    } else {

        // Check whether username or email already exists
        $query = "SELECT id FROM users
                  WHERE username = ? OR email = ?";

        $stmt = mysqli_prepare($db, $query);

        mysqli_stmt_bind_param($stmt, "ss", $username, $email);
        mysqli_stmt_execute($stmt);

        $result = mysqli_stmt_get_result($stmt);
        $existingUser = mysqli_fetch_assoc($result);

        mysqli_stmt_close($stmt);

        if ($existingUser) {

            $error = "Username or email already exists.";

        } else {

            // Securely hash password
            $hashedPassword = password_hash(
                $password,
                PASSWORD_DEFAULT
            );

            $query = "INSERT INTO users
                      (username, fullname, email, password)
                      VALUES (?, ?, ?, ?)";

            $stmt = mysqli_prepare($db, $query);

            if ($stmt) {

                mysqli_stmt_bind_param(
                    $stmt,
                    "ssss",
                    $username,
                    $fullname,
                    $email,
                    $hashedPassword
                );

                if (mysqli_stmt_execute($stmt)) {

                    mysqli_stmt_close($stmt);

                    $_SESSION['csrf_token'] =
                        bin2hex(random_bytes(32));

                    $_SESSION['successMsg'] =
                        "Registration successful! Please log in.";

                    header("Location: login.php");
                    exit();

                } else {

                    $error = "Registration failed. Please try again.";
                    mysqli_stmt_close($stmt);
                }

            } else {

                $error = "Database query could not be prepared.";
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>PostFlow | Register</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">

    <style>
        body {
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            background: #f5f6fa;
            font-family: 'Segoe UI', sans-serif;
            padding: 20px;
        }

        .register-card {
            width: 100%;
            max-width: 450px;
            background: white;
            padding: 35px;
            border-radius: 18px;
            box-shadow: 0 10px 40px rgba(0,0,0,.06);
        }

        .brand {
            text-align: center;
            font-size: 32px;
            font-weight: 800;
            margin-bottom: 25px;
        }

        .brand span {
            color: #6c63ff;
        }

        .form-control {
            height: 48px;
            font-size: 14px;
        }

        .btn-register {
            width: 100%;
            height: 49px;
            background: #6c63ff;
            color: white;
            border: none;
            border-radius: 9px;
            font-weight: 700;
        }

        .btn-register:hover {
            background: #554be8;
            color: white;
        }
    </style>
</head>

<body>

<div class="register-card">

    <div class="brand">
        Post<span>Flow.</span>
    </div>

    <h4 class="text-center fw-bold">Create an Account</h4>

    <p class="text-center text-secondary small mb-4">
        Join PostFlow and start sharing your posts.
    </p>

    <?php if ($error !== ''): ?>
        <div class="alert alert-danger">
            <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
        </div>
    <?php endif; ?>

    <form method="POST" action="register.php">

        <input type="hidden" name="csrf_token"
               value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">

        <div class="mb-3">
            <label class="form-label">Username</label>
            <input type="text" name="username"
                   class="form-control"
                   value="<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>"
                   required>
        </div>

        <div class="mb-3">
            <label class="form-label">Full Name</label>
            <input type="text" name="fullname"
                   class="form-control"
                   value="<?php echo htmlspecialchars($fullname, ENT_QUOTES, 'UTF-8'); ?>"
                   required>
        </div>

        <div class="mb-3">
            <label class="form-label">Email Address</label>
            <input type="email" name="email"
                   class="form-control"
                   value="<?php echo htmlspecialchars($email, ENT_QUOTES, 'UTF-8'); ?>"
                   required>
        </div>

        <div class="mb-3">
            <label class="form-label">Password</label>
            <input type="password" name="password"
                   class="form-control"
                   minlength="8" required>
        </div>

        <div class="mb-4">
            <label class="form-label">Confirm Password</label>
            <input type="password" name="confirm_password"
                   class="form-control"
                   minlength="8" required>
        </div>

        <button type="submit" name="register"
                class="btn-register">
            Create Account
        </button>

    </form>

    <p class="text-center mt-4 small">
        Already have an account?
        <a href="login.php">Sign In</a>
    </p>

</div>

</body>
</html>
