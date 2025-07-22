<?php
/**
 * manual_device_check.php - On-demand device status check (health endpoint version)
 */

session_start();
require_once 'db_connect.php';

header('Content-Type: application/json');
set_time_limit(10);

if (!isset($_SESSION['user_id']) || !isset($_POST['device_id'])) {
    echo json_encode(['error' => 'Invalid request']);
    exit();
}

$device_id = (int)$_POST['device_id'];

try {
    // Verify user has access to this device
    $stmt = $pdo->prepare("
        SELECT d.pnode_name, d.pnode_ip, d.username 
        FROM devices d 
        WHERE d.id = ? AND (d.username = ? OR ? = 1)
    ");
    $stmt->execute([$device_id, $_SESSION['username'], $_SESSION['admin'] ?? 0]);
    $device = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$device) {
        echo json_encode(['error' => 'Device not found or access denied']);
        exit();
    }
    
    if (!filter_var($device['pnode_ip'], FILTER_VALIDATE_IP)) {
        echo json_encode(['error' => 'Invalid IP address']);
        exit();
    }
    
    // Get consecutive failures from last check
    $stmt = $pdo->prepare("
        SELECT consecutive_failures 
        FROM device_status_log 
        WHERE device_id = ? 
        ORDER BY check_time DESC 
        LIMIT 1
    ");
    $stmt->execute([$device_id]);
    $last_check = $stmt->fetch(PDO::FETCH_ASSOC);
    $last_consecutive_failures = $last_check['consecutive_failures'] ?? 0;
    
    // Perform quick status check
    $ip = $device['pnode_ip'];
    $start_time = microtime(true);
    $status = 'Unknown';
    $response_time = null;
    $error_message = null;
    $check_method = 'manual';
    
    // Try fsockopen first (fastest)
    $connection = @fsockopen($ip, 3001, $errno, $errstr, 3);
    if ($connection) {
        fclose($connection);
        $status = 'Online';
        $response_time = microtime(true) - $start_time;
        $check_method = 'manual:fsockopen';
    } else {
        // Try port 443
        $connection = @fsockopen($ip, 443, $errno, $errstr, 2);
        if ($connection) {
            fclose($connection);
            $status = 'Online';
            $response_time = microtime(true) - $start_time;
            $check_method = 'manual:fsockopen:443';
        } else {
            $status = 'Offline';
            $response_time = microtime(true) - $start_time;
            $error_message = "Port 3001 unreachable: $errstr ($errno)";
            $check_method = 'manual:fsockopen+443';
        }
    }
    
    // Calculate consecutive failures
    $consecutive_failures = 0;
    if ($status === 'Offline' || $status === 'Error') {
        $consecutive_failures = $last_consecutive_failures + 1;
    }
    
    // Insert new status log entry
    $stmt = $pdo->prepare("
        INSERT INTO device_status_log (
            device_id, status, check_time, response_time, check_method, 
            error_message, consecutive_failures
        ) VALUES (?, ?, NOW(), ?, ?, ?, ?)
    ");
    
    $stmt->execute([
        $device_id,
        $status,
        $response_time,
        $check_method,
        $error_message,
        $consecutive_failures
    ]);
    
    // Log the manual check
    require_once 'functions.php';
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 
                   'manual_device_check', 
                   "Device: {$device['pnode_name']}, IP: $ip, Status: $status, Response: " . 
                   round($response_time * 1000, 1) . "ms");
    
    echo json_encode([
        'status' => $status,
        'response_time' => round($response_time * 1000, 1), // in milliseconds
        'device_name' => $device['pnode_name'],
        'timestamp' => date('Y-m-d H:i:s'),
        'consecutive_failures' => $consecutive_failures
    ]);
    
} catch (Exception $e) {
    error_log("Manual device check error: " . $e->getMessage());
    echo json_encode(['error' => 'Check failed: ' . $e->getMessage()]);
}
?>