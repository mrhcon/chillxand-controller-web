<?php
// db_connect.php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

try {
	$host = 'localhost';
	$dbname = 'control_login_system';
	$username = 'control_admin'; // Change to your MySQL username
	$password = 'V3@hkwT00ryqCgl#';     // Change to your MySQL password

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