<?php
// Create this as: email_test.php
// Visit it at: https://control.chillxand.com/pnode-farm/email_test.php

echo "<h2>ChillXand Email Diagnostic</h2>";

// ========== SMTP SETTINGS - UPDATE THESE ==========
$smtp_host = 'mail.control.chillxand.com';           // ← Your SMTP server
$smtp_username = 'noreply@control.chillxand.com';    // ← Your email address
$smtp_password = '?zN676xs9';         // ← PUT YOUR EMAIL PASSWORD HERE
$smtp_port = 587;                                    // ← Usually 587 or 465

// CHANGE THIS TO YOUR PERSONAL EMAIL FOR TESTING
$test_email = "mrhcon@gmail.com";  // ← PUT YOUR EMAIL HERE

echo "<h3>1. Testing Basic Mail Function</h3>";

$to = $test_email;
$subject = "Test Email from ChillXand - " . date('H:i:s');
$message = "This is a basic test email.\nSent at: " . date('Y-m-d H:i:s');
$headers = "From: noreply@control.chillxand.com\r\n";

if (mail($to, $subject, $message, $headers)) {
    echo "<p style='color: green;'>✓ mail() function returned TRUE</p>";
} else {
    echo "<p style='color: red;'>✗ mail() function returned FALSE</p>";
}

echo "<h3>2. Server Configuration</h3>";
echo "<pre>";
echo "PHP Version: " . phpversion() . "\n";
echo "Operating System: " . php_uname() . "\n";
echo "Mail function exists: " . (function_exists('mail') ? 'YES' : 'NO') . "\n";

echo "\nMail Configuration:\n";
echo "SMTP: " . (ini_get('SMTP') ?: 'Not set') . "\n";
echo "smtp_port: " . (ini_get('smtp_port') ?: 'Not set') . "\n";
echo "sendmail_from: " . (ini_get('sendmail_from') ?: 'Not set') . "\n";
echo "sendmail_path: " . (ini_get('sendmail_path') ?: 'Not set') . "\n";
echo "</pre>";

echo "<h3>3. Error Log Check</h3>";
$lastError = error_get_last();
if ($lastError) {
    echo "<p>Last PHP Error:</p>";
    echo "<pre>" . print_r($lastError, true) . "</pre>";
} else {
    echo "<p>No recent PHP errors logged.</p>";
}

echo "<h3>4. Testing Socket Connection</h3>";
$smtp_servers = [
    'mail.control.chillxand.com' => 587,
    'smtp.control.chillxand.com' => 587,
    'control.chillxand.com' => 587,
    'mail.control.chillxand.com' => 25,
    'smtp.control.chillxand.com' => 25
];

foreach ($smtp_servers as $host => $port) {
    echo "Testing $host:$port... ";
    $connection = @fsockopen($host, $port, $errno, $errstr, 5);
    if ($connection) {
        echo "<span style='color: green;'>✓ Connected</span><br>";
        fclose($connection);
    } else {
        echo "<span style='color: red;'>✗ Failed ($errno: $errstr)</span><br>";
    }
}

echo "<h3>6. Testing SMTP Authentication</h3>";
echo "Using settings: $smtp_host:$smtp_port with username: $smtp_username<br>";

if ($smtp_password === 'YOUR_EMAIL_PASSWORD_HERE') {
    echo "<p style='color: red;'>⚠️ Please update the SMTP password in this script!</p>";
} else {
    echo "Testing SMTP authentication...<br>";
    
    // Test SMTP connection with authentication
    $connection = @fsockopen($smtp_host, $smtp_port, $errno, $errstr, 10);
    if ($connection) {
        echo "✓ Connected to SMTP server<br>";
        
        // Read initial response
        $response = fgets($connection, 1024);
        echo "Server response: " . trim($response) . "<br>";
        
        // Send EHLO
        fputs($connection, "EHLO test\r\n");
        $response = fgets($connection, 1024);
        echo "EHLO response: " . trim($response) . "<br>";
        
        // Check if AUTH is supported
        while ($line = fgets($connection, 1024)) {
            if (strpos($line, 'AUTH') !== false) {
                echo "✓ Server supports authentication: " . trim($line) . "<br>";
                break;
            }
            if (trim($line) === '' || strpos($line, '250 ') === 0) break;
        }
        
        fputs($connection, "QUIT\r\n");
        fclose($connection);
        
        // Now try sending actual email via SMTP
        echo "<br>Attempting to send test email via SMTP...<br>";
        $smtp_result = sendTestEmailSMTP($test_email, $smtp_host, $smtp_username, $smtp_password, $smtp_port);
        
        if ($smtp_result) {
            echo "<span style='color: green;'>✓ SMTP email sent successfully!</span><br>";
        } else {
            echo "<span style='color: red;'>✗ SMTP email failed</span><br>";
        }
        
    } else {
        echo "<span style='color: red;'>✗ Could not connect to SMTP server: $errstr ($errno)</span><br>";
    }
}

// Simple SMTP email function for testing
function sendTestEmailSMTP($to, $host, $username, $password, $port) {
    $connection = @fsockopen($host, $port, $errno, $errstr, 10);
    if (!$connection) return false;
    
    try {
        // SMTP conversation
        fgets($connection, 1024); // Initial response
        
        fputs($connection, "EHLO test\r\n");
        while ($line = fgets($connection, 1024)) {
            if (trim($line) === '' || strpos($line, '250 ') === 0) break;
        }
        
        fputs($connection, "AUTH LOGIN\r\n");
        fgets($connection, 1024);
        
        fputs($connection, base64_encode($username) . "\r\n");
        fgets($connection, 1024);
        
        fputs($connection, base64_encode($password) . "\r\n");
        $auth_response = fgets($connection, 1024);
        
        if (strpos($auth_response, '235') === false) {
            echo "Authentication failed: " . trim($auth_response) . "<br>";
            fclose($connection);
            return false;
        }
        
        fputs($connection, "MAIL FROM: <$username>\r\n");
        fgets($connection, 1024);
        
        fputs($connection, "RCPT TO: <$to>\r\n");
        fgets($connection, 1024);
        
        fputs($connection, "DATA\r\n");
        fgets($connection, 1024);
        
        $email_data = "From: $username\r\n";
        $email_data .= "To: $to\r\n";
        $email_data .= "Subject: SMTP Test from ChillXand - " . date('H:i:s') . "\r\n";
        $email_data .= "\r\n";
        $email_data .= "This is an SMTP test email sent at " . date('Y-m-d H:i:s') . "\r\n";
        $email_data .= "If you receive this, your SMTP settings are working!\r\n";
        $email_data .= "\r\n.\r\n";
        
        fputs($connection, $email_data);
        $send_response = fgets($connection, 1024);
        
        fputs($connection, "QUIT\r\n");
        fclose($connection);
        
        return strpos($send_response, '250') !== false;
        
    } catch (Exception $e) {
        fclose($connection);
        return false;
    }
}

echo "<h3>Instructions:</h3>";
echo "<ol>";
echo "<li><strong>Check your personal email</strong> (including spam folder) for the test email</li>";
echo "<li><strong>Look at the server configuration</strong> above</li>";
echo "<li><strong>If socket connections fail</strong>, your hosting may not allow SMTP</li>";
echo "<li><strong>Contact your hosting provider</strong> if basic mail() fails</li>";
echo "</ol>";

echo "<p><em>Delete this file after testing!</em></p>";
?>

<style>
body { font-family: Arial, sans-serif; max-width: 900px; margin: 20px auto; padding: 20px; }
pre { background: #f5f5f5; padding: 10px; border: 1px solid #ddd; }
h3 { color: #333; border-bottom: 1px solid #eee; padding-bottom: 5px; }
</style>