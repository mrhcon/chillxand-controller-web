<?php
session_start();
require_once 'db_connect.php';
require_once 'functions.php';

// Redirect to dashboard if already logged in
if (isset($_SESSION['user_id'])) {
    header("Location: user_dashboard.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $first_name = trim($_POST['first_name']);
    $last_name = trim($_POST['last_name']);
    $country = trim($_POST['country']);
    $password = trim($_POST['password']);
    $confirm_password = trim($_POST['confirm_password']);
    
    // Validate input
    if (empty($username) || empty($email) || empty($first_name) || empty($last_name) || empty($country) || empty($password) || empty($confirm_password)) {
        $error = "Please fill in all fields.";
        logInteraction($pdo, null, $username, 'register_failed', 'Empty fields');
    } elseif ($password !== $confirm_password) {
        $error = "Passwords do not match.";
        logInteraction($pdo, null, $username, 'register_failed', 'Password mismatch');
    } elseif (strlen($username) < 3 || strlen($username) > 50) {
        $error = "Username must be between 3 and 50 characters.";
        logInteraction($pdo, null, $username, 'register_failed', 'Invalid username length');
    } elseif (strlen($password) < 6) {
        $error = "Password must be at least 6 characters.";
        logInteraction($pdo, null, $username, 'register_failed', 'Password too short');
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email format.";
        logInteraction($pdo, null, $username, 'register_failed', 'Invalid email format');
    } elseif (strlen($first_name) > 50 || strlen($last_name) > 50) {
        $error = "First name and last name must be 50 characters or less.";
        logInteraction($pdo, null, $username, 'register_failed', 'Invalid name length');
    } elseif (strlen($country) > 100) {
        $error = "Country name must be 100 characters or less.";
        logInteraction($pdo, null, $username, 'register_failed', 'Invalid country length');
    } else {
        try {
            // Check for duplicate username
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
            $stmt->execute([$username]);
            if ($stmt->fetchColumn() > 0) {
                $error = "Username already exists.";
                logInteraction($pdo, null, $username, 'register_failed', 'Duplicate username');
            } else {
                // Check for duplicate email - FIXED
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
                $stmt->execute([$email]);
                if ($stmt->fetchColumn() > 0) {
                    $error = "Email already exists.";
                    logInteraction($pdo, null, $username, 'register_failed', 'Duplicate email');
                } else {
                    // Create new user
                    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("INSERT INTO users (username, email, first_name, last_name, country, password) VALUES (?, ?, ?, ?, ?, ?)");
                    $stmt->execute([$username, $email, $first_name, $last_name, $country, $hashed_password]);
                    
                    // Get the new user's ID
                    $user_id = $pdo->lastInsertId();
                    
                    // Log successful registration
                    logInteraction($pdo, $user_id, $username, 'register_success');
                    
                    // Automatically log in the new user
                    $_SESSION['user_id'] = $user_id;
                    $_SESSION['username'] = $username;
                    header("Location: user_dashboard.php");
                    exit();
                }
            }
        } catch (PDOException $e) {
            $error = "Error: " . $e->getMessage();
            logInteraction($pdo, null, $username, 'register_failed', 'Database error: ' . $e->getMessage());
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link rel="icon" type="image/x-icon" href="images/favicon.ico">
    <link rel="icon" type="image/png" sizes="32x32" href="images/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="images/favicon-16x16.png">    
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="login-container">
        <h2>Register</h2>
        <?php if (isset($error)): ?>
            <p class="error"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        <form method="POST" action="">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="first_name">First Name:</label>
                <input type="text" id="first_name" name="first_name" required>
            </div>
            <div class="form-group">
                <label for="last_name">Last Name:</label>
                <input type="text" id="last_name" name="last_name" required>
            </div>
            <div class="form-group">
                <label for="country">Country:</label>
                <input type="text" id="country" name="country" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirm Password:</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>
            <button type="submit">Register</button>
        </form>
        <p>Already have an account? <a href="login.php">Login here</a></p>
    </div>
</body>
</html>