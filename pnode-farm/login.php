<?php
session_start();
require_once 'db_connect.php';
require_once 'functions.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);
    
    if (empty($username) || empty($password)) {
        $error = "Please fill in all fields.";
        logInteraction($pdo, null, $username, 'login_failed', 'Empty username or password');
    } else {
        try {
            $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user && password_verify($password, $user['password'])) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                logInteraction($pdo, $user['id'], $username, 'login_success');
                header("Location: dashboard.php");
                exit();
            } else {
                $error = "Invalid username or password.";
                logInteraction($pdo, null, $username, 'login_failed', 'Invalid credentials');
            }
        } catch (PDOException $e) {
            $error = "Error: " . $e->getMessage();
            logInteraction($pdo, null, $username, 'login_failed', 'Database error: ' . $e->getMessage());
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login System</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="login-container">
    	<img src="ChillXand-logo.png"></br>
        <h2>ChillXand<br>pNode Management Console</h2>
		<h2>Login</h2>
        <?php if (isset($error)): ?>
            <p class="error"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        <form method="POST" action="">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for_banner"password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <p>Don't have an account? <a href="register.php">Register here</a></p>
    </div>
</body>
</html>