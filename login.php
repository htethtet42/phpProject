
<?php
session_start();
require "connect.php";

// Redirect if already logged in
if (isset($_SESSION['admin_id']) || isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit();
}

$error = "";
$username = "";

// Generate CSRF token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Handle Login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {

    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $csrf_token = $_POST['csrf_token'] ?? '';

    if (!hash_equals($_SESSION['csrf_token'], $csrf_token)) {

        $error = "Invalid request. Please refresh the page.";

    } elseif ($username === '' || $password === '') {

        $error = "Please enter username and password.";

    } else {

        // First: Check Administrator account
        $query = "SELECT id, username, fullname, password
                  FROM admins
                  WHERE username = ?";

        $stmt = mysqli_prepare($db, $query);
        mysqli_stmt_bind_param($stmt, "s", $username);
        mysqli_stmt_execute($stmt);

        $result = mysqli_stmt_get_result($stmt);
        $admin = mysqli_fetch_assoc($result);

        mysqli_stmt_close($stmt);

        if ($admin) {

            if (password_verify($password, $admin['password'])) {

                session_regenerate_id(true);

                $_SESSION['admin_id'] = $admin['id'];
                $_SESSION['admin_name'] = $admin['fullname'];

                $_SESSION['successMsg'] =
                    "Welcome back, " . $admin['fullname'] . "!";

                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

                header("Location: index.php");
                exit();

            } else {

                $error = "Invalid username or password.";

            }

        } else {

            // Second: Check Normal User account
            $query = "SELECT id, username, fullname, password
                      FROM users
                      WHERE username = ?";

            $stmt = mysqli_prepare($db, $query);
            mysqli_stmt_bind_param($stmt, "s", $username);
            mysqli_stmt_execute($stmt);

            $result = mysqli_stmt_get_result($stmt);
            $user = mysqli_fetch_assoc($result);

            mysqli_stmt_close($stmt);

            if ($user && password_verify($password, $user['password'])) {

                session_regenerate_id(true);

                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['fullname'];

                $_SESSION['successMsg'] =
                    "Welcome back, " . $user['fullname'] . "!";

                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

                header("Location: index.php");
                exit();

            } else {

                $error = "Invalid username or password.";

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

    <title>PostFlow | Admin Login</title>

    <!-- Bootstrap -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css"
          rel="stylesheet">

    <!-- Bootstrap Icons -->
    <link rel="stylesheet"
          href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">

    <!-- Google Font -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
          rel="stylesheet">

    <style>

        :root {
            --primary: #6c63ff;
            --primary-dark: #554be8;
            --background: #f5f6fa;
            --text: #25283b;
            --muted: #9295a5;
            --border: #eceef4;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 25px;
            background: var(--background);
            font-family: 'Inter', 'Segoe UI', sans-serif;
            color: var(--text);
        }

        .login-wrapper {
            width: 100%;
            max-width: 440px;
        }

        /* Brand */

        .brand {
            text-align: center;
            margin-bottom: 30px;
        }

        .brand h1 {
            font-size: 34px;
            font-weight: 800;
            letter-spacing: -1.5px;
        }

        .brand span {
            color: var(--primary);
        }

        .brand p {
            color: var(--muted);
            font-size: 14px;
            margin-top: 7px;
        }

        /* Login Card */

        .login-card {
            background: #fff;
            padding: 38px;
            border: 1px solid var(--border);
            border-radius: 20px;

            box-shadow:
                0 10px 40px rgba(30, 35, 70, .06);
        }

        .login-icon {
            width: 58px;
            height: 58px;
            border-radius: 16px;
            background: #eeecff;
            color: var(--primary);

            display: flex;
            align-items: center;
            justify-content: center;

            font-size: 25px;
            margin-bottom: 22px;
        }

        .login-heading h2 {
            font-size: 23px;
            font-weight: 750;
            margin-bottom: 8px;
        }

        .login-heading p {
            color: var(--muted);
            font-size: 13px;
            margin-bottom: 28px;
        }

        /* Form */

        .form-label {
            font-size: 13px;
            font-weight: 700;
            margin-bottom: 9px;
        }

        .input-group {
            border: 1px solid #e4e6ef;
            border-radius: 10px;
            overflow: hidden;
        }

        .input-group-text {
            background: #fff;
            border: none;
            color: var(--muted);
            padding-left: 15px;
        }

        .form-control {
            height: 49px;
            border: none;
            font-size: 13px;
            box-shadow: none !important;
        }

        .input-group:focus-within {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(108, 99, 255, .10);
        }

        .password-toggle {
            background: white;
            border: none;
            color: var(--muted);
            padding: 0 15px;
            cursor: pointer;
        }

        .password-toggle:hover {
            color: var(--primary);
        }

        /* Login Button */

        .btn-login {
            width: 100%;
            height: 51px;
            background: var(--primary);
            border: none;
            border-radius: 10px;
            color: white;
            font-size: 14px;
            font-weight: 700;
            margin-top: 10px;
            transition: .25s;
        }

        .btn-login:hover {
            background: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: 0 7px 18px rgba(108, 99, 255, .23);
        }

        /* Footer */

        .login-footer {
            text-align: center;
            margin-top: 25px;
            color: var(--muted);
            font-size: 12px;
        }

        .login-footer i {
            color: var(--primary);
        }

        /* Alert */

        .alert {
            font-size: 13px;
            border-radius: 10px;
        }

        @media (max-width: 480px) {

            .login-card {
                padding: 27px 22px;
            }

            .brand h1 {
                font-size: 30px;
            }

        }

    </style>

</head>

<body>

    <div class="login-wrapper">

        <!-- Brand -->
        <div class="brand">

            <h1>
                Post<span>Flow.</span>
            </h1>

            <p>Content Management System</p>

        </div>


        <!-- Login Card -->
        <div class="login-card">

            <div class="login-icon">
                <i class="bi bi-shield-lock-fill"></i>
            </div>

            <div class="login-heading">

                <h2>Welcome Back!</h2>

                <p>
                    Sign in to access your PostFlow dashboard.
                </p>

            </div>


            <!-- Error Message -->
            <?php if (!empty($error)): ?>

                <div class="alert alert-danger d-flex align-items-center gap-2">

                    <i class="bi bi-exclamation-circle-fill"></i>

                    <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>

                </div>

            <?php endif; ?>


            <!-- Login Form -->
            <form method="POST" action="login.php">

                <input type="hidden"
                       name="csrf_token"
                       value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">


                <!-- Username -->
                <div class="mb-4">

                    <label class="form-label">
                        Username
                    </label>

                    <div class="input-group">

                        <span class="input-group-text">
                            <i class="bi bi-person"></i>
                        </span>

                        <input
                            type="text"
                            name="username"
                            class="form-control"
                            placeholder="Enter your username"
                            value="<?php echo htmlspecialchars($username ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                            autocomplete="username"
                            required
                        >

                    </div>

                </div>


                <!-- Password -->
                <div class="mb-4">

                    <label class="form-label">
                        Password
                    </label>

                    <div class="input-group">

                        <span class="input-group-text">
                            <i class="bi bi-lock"></i>
                        </span>

                        <input
                            type="password"
                            name="password"
                            id="password"
                            class="form-control"
                            placeholder="Enter your password"
                            autocomplete="current-password"
                            required
                        >

                        <button
                            type="button"
                            class="password-toggle"
                            onclick="togglePassword()"
                            aria-label="Show password"
                        >
                            <i class="bi bi-eye" id="eyeIcon"></i>
                        </button>

                    </div>

                </div>


                <!-- Login Button -->
                <button
                    type="submit"
                    name="login"
                    class="btn-login"
                >

                    <i class="bi bi-box-arrow-in-right me-2"></i>

                    Sign In to Dashboard

                </button>

                <p class="text-center mt-3 small">
                    Don't have an account?
                    <a href="register.php">Create an Account</a>
                </p>

            </form>

        </div>


        <!-- Footer -->
        <div class="login-footer">

            <p>
                <i class="bi bi-shield-check"></i>
                Secure Administrator Access
            </p>

            <p>
                © <?php echo date("Y"); ?> PostFlow CMS.
                All rights reserved.
            </p>

        </div>

    </div>


    <!-- Password Visibility -->
    <script>

        function togglePassword() {

            const password = document.getElementById("password");
            const icon = document.getElementById("eyeIcon");

            if (password.type === "password") {

                password.type = "text";

                icon.classList.remove("bi-eye");
                icon.classList.add("bi-eye-slash");

            } else {

                password.type = "password";

                icon.classList.remove("bi-eye-slash");
                icon.classList.add("bi-eye");

            }

        }

    </script>

</body>
</html>
