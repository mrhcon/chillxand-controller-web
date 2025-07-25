<?php
session_start();
require_once 'db_connect.php';
require_once 'functions.php';

$step = $_GET['step'] ?? 'request';
$username = $_POST['username'] ?? '';
$current_password = $_POST['current_password'] ?? '';
$reset_code = $_POST['reset_code'] ?? '';
$new_password = $_POST['new_password'] ?? '';
$confirm_password = $_POST['confirm_password'] ?? '';
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if ($step === 'request') {
        // Step 1: Request reset code
        if (empty($username) || empty($current_password)) {
            $error = "Please fill in all fields.";
        } else {
            try {
                // Verify username and password
                $stmt = $pdo->prepare("SELECT id, username, email, password FROM users WHERE username = ?");
                $stmt->execute([$username]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($user && password_verify($current_password, $user['password'])) {
                    // Check for existing unused reset codes and mark them as used
                    $stmt = $pdo->prepare("UPDATE password_resets SET used = TRUE WHERE user_id = ? AND used = FALSE");
                    $stmt->execute([$user['id']]);
                    
                    // Generate and store reset code
                    $reset_code = generateResetCode();
                    $expires_at = date('Y-m-d H:i:s', strtotime('+1 hour'));
                    
                    $stmt = $pdo->prepare("INSERT INTO password_resets (user_id, username, reset_code, expires_at) VALUES (?, ?, ?, ?)");
                    $stmt->execute([$user['id'], $user['username'], $reset_code, $expires_at]);
                    
                    // Send reset code via email
                    if (sendResetCodeEmail($user['email'], $user['username'], $reset_code)) {
                        $success = "A reset code has been sent to your email.";
                        $step = 'reset';
                        logInteraction($pdo, $user['id'], $user['username'], 'reset_code_sent', 'Reset code sent successfully');
                    } else {
                        $error = "Failed to send reset code email.";
                        logInteraction($pdo, $user['id'], $user['username'], 'reset_code_email_failed', 'Email sending failed');
                    }
                } else {
                    $error = "Invalid username or password.";
                    logInteraction($pdo, 0, $username, 'reset_password_failed', 'Invalid credentials');
                }
            } catch (PDOException $e) {
                $error = "Error: " . $e->getMessage();
                logInteraction($pdo, 0, $username, 'reset_password_failed', 'Database error: ' . $e->getMessage());
            }
        }
    } elseif ($step === 'reset') {
        // Step 2: Validate reset code and update password
        if (empty($username) || empty($reset_code) || empty($new_password) || empty($confirm_password)) {
            $error = "Please fill in all fields.";
        } elseif ($new_password !== $confirm_password) {
            $error = "Passwords do not match.";
        } elseif (strlen($new_password) < 8) {
            $error = "New password must be at least 8 characters long.";
        } else {
            try {
                // Verify reset code
                $stmt = $pdo->prepare("
                    SELECT user_id 
                    FROM password_resets 
                    WHERE username = ? AND reset_code = ? AND expires_at > NOW() AND used = FALSE
                ");
                $stmt->execute([$username, $reset_code]);
                $reset = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($reset) {
                    // Update password
                    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
                    $stmt->execute([$hashed_password, $reset['user_id']]);
                    
                    // Mark reset code as used
                    $stmt = $pdo->prepare("UPDATE password_resets SET used = TRUE WHERE username = ? AND reset_code = ?");
                    $stmt->execute([$username, $reset_code]);
                    
                    $success = "Password reset successfully. <a href='login.php'>Login with your new password</a>";
                    logInteraction($pdo, $reset['user_id'], $username, 'password_reset_success', 'Password reset completed');
                    $step = 'complete'; // Show completion message
                } else {
                    $error = "Invalid or expired reset code.";
                    logInteraction($pdo, 0, $username, 'reset_code_invalid', 'Invalid or expired reset code');
                }
            } catch (PDOException $e) {
                $error = "Error: " . $e->getMessage();
                logInteraction($pdo, 0, $username, 'reset_password_failed', 'Database error: ' . $e->getMessage());
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
    <title>Reset Password</title>
    <link rel="icon" type="image/x-icon" href="images/favicon.ico">
    <link rel="icon" type="image/png" sizes="32x32" href="images/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="images/favicon-16x16.png">    
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="login-container">
        <h2>Reset Password</h2>
        <?php if ($error): ?>
            <p class="error"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        <?php if ($success): ?>
            <p class="success"><?php echo $success; ?></p>
        <?php endif; ?>
        
        <?php if ($step === 'request'): ?>
            <p>Enter your username and current password to receive a reset code via email.</p>
            <form method="POST" action="reset_password.php?step=request">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($username); ?>" required>
                </div>
                <div class="form-group">
                    <label for="current_password">Current Password:</label>
                    <input type="password" id="current_password" name="current_password" required>
                </div>
                <button type="submit">Request Reset Code</button>
            </form>
        <?php elseif ($step === 'reset'): ?>
            <p>Check your email for the reset code and enter it below with your new password.</p>
            <form method="POST" action="reset_password.php?step=reset">
                <input type="hidden" name="username" value="<?php echo htmlspecialchars($username); ?>">
                <div class="form-group">
                    <label for="reset_code">Reset Code (from email):</label>
                    <input type="text" id="reset_code" name="reset_code" maxlength="6" required>
                </div>
                <div class="form-group">
                    <label for="new_password">New Password (min 8 characters):</label>
                    <input type="password" id="new_password" name="new_password" minlength="8" required>
                </div>
                <div class="form-group">
                    <label for="confirm_password">Confirm New Password:</label>
                    <input type="password" id="confirm_password" name="confirm_password" minlength="8" required>
                </div>
                <button type="submit">Reset Password</button>
            </form>
        <?php endif; ?>
        
        <p><a href="login.php">Back to Login</a></p>
        
        <?php if ($step === 'reset'): ?>
            <p><a href="reset_password.php">Request a new reset code</a></p>
        <?php endif; ?>
    </div>
</body>
</html>