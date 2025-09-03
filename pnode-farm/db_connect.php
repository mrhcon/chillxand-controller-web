<?php
// db_connect.php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Load configuration
$config = include __DIR__ . '/config.php';

// Check if config loaded successfully
if (!$config || !isset($config['database'])) {
    error_log("Configuration file not found or invalid. Please copy config.example.php to config.php and update with your credentials.");
    $pdo = null;
    return;
}

$db_config = $config['database'];

try {
    $host = $db_config['host'];
    $dbname = $db_config['dbname'];
    $username = $db_config['username'];
    $password = $db_config['password'];

    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    error_log("Database connection successful for $dbname on $host");
} catch (PDOException $e) {
    $error_message = "Database connection failed: " . $e->getMessage();
    error_log($error_message);
    // Avoid die() to allow error display in admin_devices.php
    $pdo = null;
}
?>