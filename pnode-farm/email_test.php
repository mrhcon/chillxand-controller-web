<?php
// Create this as: simple_test.php
// Change the email below to yours and visit the page

$your_email = "your-email@gmail.com"; // ← CHANGE THIS

$to = $your_email;
$subject = "Simple Test - " . date('H:i:s');
$message = "This is a simple test email.\nSent from ChillXand at: " . date('Y-m-d H:i:s');

$headers = "From: ChillXand Test <noreply@control.chillxand.com>\r\n";
$headers .= "Reply-To: support@control.chillxand.com\r\n";
$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

echo "<h2>Sending simple test email...</h2>";

if (mail($to, $subject, $message, $headers)) {
    echo "<p style='color: green;'>✓ Email sent successfully to: $to</p>";
    echo "<p><strong>Check your email (and spam folder) now!</strong></p>";
} else {
    echo "<p style='color: red;'>✗ Email failed to send</p>";
}

echo "<p>If you don't receive the email within 5 minutes, it may be:</p>";
echo "<ul>";
echo "<li>Going to your spam folder</li>";
echo "<li>Being blocked by your email provider</li>";
echo "<li>The server's mail reputation needs improvement</li>";
echo "</ul>";
?>