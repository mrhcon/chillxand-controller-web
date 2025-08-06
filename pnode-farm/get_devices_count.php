<?php
// CREATE NEW FILE: get_devices_count.php
session_start();
require_once 'db_connect.php';

header('Content-Type: application/json');

// Check if user is logged in and is admin
if (!isset($_SESSION['user_id']) || !$_SESSION['admin']) {
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit();
}

try {
    // Get total device count
    $stmt = $pdo->prepare("SELECT COUNT(*) as device_count FROM devices");
    $stmt->execute();
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    
    echo json_encode([
        'success' => true,
        'device_count' => (int)$result['device_count']
    ]);
    
} catch (PDOException $e) {
    error_log("Error getting device count: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'error' => 'Database error'
    ]);
}
?>