<?php
// get_device_status_logs.php - Fetch device status logs instead of user interactions
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
require_once 'db_connect.php';

if (!isset($pdo) || $pdo === null) {
    echo json_encode(['error' => 'Database connection error.']);
    error_log("PDO object is null in get_device_status_logs.php.");
    exit();
}

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['error' => 'User not logged in.']);
    error_log("No user_id in session for get_device_status_logs.php.");
    exit();
}

$device_id = isset($_POST['device_id']) ? (int)$_POST['device_id'] : 0;
$page = isset($_POST['page']) ? (int)$_POST['page'] : 1;
$limit = isset($_POST['limit']) ? (int)$_POST['limit'] : 10;
$offset = ($page - 1) * $limit;

try {
    // Verify user has access to this device
    $stmt = $pdo->prepare("SELECT pnode_name, pnode_ip FROM devices WHERE id = :device_id AND (username = :username OR :admin = 1)");
    $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
    $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
    $stmt->bindValue(':admin', $_SESSION['admin'] ?? 0, PDO::PARAM_INT);
    $stmt->execute();
    $device = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$device) {
        echo json_encode(['error' => 'Device not found or not authorized.']);
        error_log("Device not found or unauthorized: ID=$device_id, User={$_SESSION['username']}");
        exit();
    }

    // Count total status logs for this device
    $count_sql = "SELECT COUNT(*) FROM device_status_log WHERE device_id = :device_id";
    $stmt = $pdo->prepare($count_sql);
    $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
    $stmt->execute();
    $total_logs = $stmt->fetchColumn();
    $total_pages = ceil($total_logs / $limit);

    // Fetch paginated device status logs
    $sql = "
        SELECT status, check_time, response_time, check_method, error_message, 
               health_status, atlas_registered, pod_status, xandminer_status, xandminerd_status,
               cpu_load_avg, memory_percent, consecutive_failures
        FROM device_status_log 
        WHERE device_id = :device_id 
        ORDER BY check_time DESC 
        LIMIT :limit OFFSET :offset
    ";
    
    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
    $stmt->bindValue(':limit', (int)$limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', (int)$offset, PDO::PARAM_INT);
    $stmt->execute();
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode([
        'logs' => $logs,
        'total_pages' => $total_pages,
        'current_page' => $page,
        'device_name' => $device['pnode_name']
    ]);
} catch (PDOException $e) {
    echo json_encode(['error' => 'Error fetching status logs: ' . $e->getMessage()]);
    error_log("PDOException in get_device_status_logs.php: " . $e->getMessage());
}
?>