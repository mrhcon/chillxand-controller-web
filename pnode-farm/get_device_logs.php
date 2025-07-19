<?php
// get_device_logs.php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
require_once 'db_connect.php';

if (!isset($pdo) || $pdo === null) {
    echo json_encode(['error' => 'Database connection error.']);
    error_log("PDO object is null in get_device_logs.php.");
    exit();
}

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['error' => 'User not logged in.']);
    error_log("No user_id in session for get_device_logs.php.");
    exit();
}

$device_id = isset($_POST['device_id']) ? (int)$_POST['device_id'] : 0;
$page = isset($_POST['page']) ? (int)$_POST['page'] : 1;
$limit = isset($_POST['limit']) ? (int)$_POST['limit'] : 10;
$offset = ($page - 1) * $limit;

try {
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

    $device_name_pattern = "%Device: {$device['pnode_name']}%";
    $ip_pattern = "%IP: {$device['pnode_ip']}%";
    $where_conditions = [
        "action IN ('device_status_check_success', 'device_status_check_failed', 'device_register_success', 'device_edit_success', 'device_delete_success')",
        "(details LIKE :device_name_pattern OR details LIKE :ip_pattern)"
    ];
    $params = [
        ':device_name_pattern' => $device_name_pattern,
        ':ip_pattern' => $ip_pattern
    ];
    if (!($_SESSION['admin'] ?? 0)) {
        $where_conditions[] = "user_id = :user_id";
        $params[':user_id'] = $_SESSION['user_id'];
    }

    // Count total logs
    $count_sql = "SELECT COUNT(*) FROM user_interactions WHERE " . implode(" AND ", $where_conditions);
    $stmt = $pdo->prepare($count_sql);
    foreach ($params as $key => $value) {
        $type = ($key === ':user_id') ? PDO::PARAM_INT : PDO::PARAM_STR;
        $stmt->bindValue($key, $value, $type);
    }
    $stmt->execute();
    $total_logs = $stmt->fetchColumn();
    $total_pages = ceil($total_logs / $limit);

    // Fetch paginated logs
    $sql = "SELECT action, timestamp, details FROM user_interactions WHERE " . implode(" AND ", $where_conditions) . " ORDER BY timestamp DESC LIMIT :limit OFFSET :offset";
    $stmt = $pdo->prepare($sql);
    $params[':limit'] = (int)$limit;
    $params[':offset'] = (int)$offset;
    foreach ($params as $key => $value) {
        $type = (in_array($key, [':user_id', ':limit', ':offset'])) ? PDO::PARAM_INT : PDO::PARAM_STR;
        $stmt->bindValue($key, $value, $type);
    }
    $stmt->execute();
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode([
        'logs' => $logs,
        'total_pages' => $total_pages,
        'current_page' => $page
    ]);
} catch (PDOException $e) {
    echo json_encode(['error' => 'Error fetching logs: ' . $e->getMessage()]);
    error_log("PDOException in get_device_logs.php: " . $e->getMessage());
}
?>