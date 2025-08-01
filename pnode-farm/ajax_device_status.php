<?php
session_start();
require_once 'db_connect.php';
require_once 'functions.php';

// Set content type to JSON
header('Content-Type: application/json');

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Not authenticated']);
    exit();
}

// Get device ID from request
$device_id = $_GET['device_id'] ?? null;
if (!$device_id) {
    http_response_code(400);
    echo json_encode(['error' => 'Device ID required']);
    exit();
}

try {
    // Get user admin status if not already in session
    if (!isset($_SESSION['admin'])) {
        $stmt = $pdo->prepare("SELECT admin FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        $_SESSION['admin'] = $user['admin'] ?? 0;
    }
    
    // Verify device belongs to user (or user is admin)
    if ($_SESSION['admin']) {
        // Admin can access any device
        $stmt = $pdo->prepare("SELECT id, pnode_name, pnode_ip FROM devices WHERE id = ?");
        $stmt->execute([$device_id]);
    } else {
        // Regular user can only access their own devices
        $stmt = $pdo->prepare("SELECT id, pnode_name, pnode_ip FROM devices WHERE id = ? AND username = ?");
        $stmt->execute([$device_id, $_SESSION['username']]);
    }
    
    $device = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$device) {
        http_response_code(404);
        echo json_encode(['error' => 'Device not found']);
        exit();
    }
    
    // Get latest status for this device
    $cached_statuses = getLatestDeviceStatuses($pdo, [$device_id]);
    $cached_status = $cached_statuses[$device_id] ?? [
        'status' => 'Not Initialized',
        'is_stale' => true,
        'error_message' => 'Device has not been checked yet'
    ];
    
    // Parse health data
    $summary = parseCachedDeviceHealth($cached_status);
    
    // Determine overall status (must match the logic from dashboard.php)
    $overall_status = 'Unknown';
    if ($cached_status['status'] === 'Online') {
        if ($summary['health_status'] === 'pass') {
            $overall_status = 'Healthy';
        } elseif ($summary['health_status'] === 'fail') {
            $overall_status = 'Online (Issues)';
        } else {
            $overall_status = 'Online';
        }
    } elseif ($cached_status['status'] === 'Offline') {
        $overall_status = 'Offline';
    } else {
        $overall_status = $cached_status['status'];
    }
    
    // Return JSON response
    echo json_encode([
        'success' => true,
        'device_id' => $device_id,
        'status' => $cached_status['status'],
        'overall_status' => $overall_status,
        'status_age' => $cached_status['age_minutes'],
        'status_stale' => $cached_status['is_stale'],
        'last_check' => $cached_status['check_time'],
        'response_time' => $cached_status['response_time'],
        'consecutive_failures' => $cached_status['consecutive_failures'],
        'health_status' => $cached_status['health_status'],
        'summary' => $summary,
        'timestamp' => date('M j, H:i')
    ]);
    
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}
?>