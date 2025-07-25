<?php
// Simple email test - just send ONE email and show what happens
$your_email = "mrhcon@gmail.com"; // ← CHANGE THIS

echo "<h2>Simple Email Test</h2>";

// Send one test email
$to = $your_email;
$subject = "Test Email - " . date('H:i:s');
$message = "This is a test email sent at " . date('Y-m-d H:i:s');
$headers = "From: test@control.chillxand.com";

echo "Sending email to: $your_email<br><br>";

if (mail($to, $subject, $message, $headers)) {
    echo "✓ PHP mail() returned TRUE<br><br>";
} else {
    echo "✗ PHP mail() returned FALSE<br><br>";
}

// Check what's in the mail queue
echo "<strong>Mail Queue:</strong><br>";
$queue = shell_exec('mailq 2>&1');
echo "<pre>" . htmlspecialchars($queue) . "</pre>";

// Check recent mail log
echo "<strong>Recent Mail Log:</strong><br>";
$log = shell_exec('tail -10 /var/log/mail.log 2>&1');
if (!$log) {
    $log = shell_exec('tail -10 /var/log/maillog 2>&1');
}
if (!$log) {
    $log = "No mail log found";
}
echo "<pre>" . htmlspecialchars($log) . "</pre>";

echo "<p>Check your email now. If nothing arrives in 2 minutes, there's a delivery problem.</p>";
?>