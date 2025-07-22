<?php
session_start();
require_once 'db_connect.php';
require_once 'functions.php';

// Check if PDO is initialized
if (!isset($pdo) || $pdo === null) {
    error_log("PDO object is null in device_details.php. Check db_connect.php configuration.");
    die("Database connection error. Please contact the administrator.");
}

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Validate device_id
$device_id = isset($_GET['device_id']) ? (int)$_GET['device_id'] : 0;
if ($device_id <= 0) {
    $error = "Invalid device ID.";
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_details_access_failed', $error);
}

// Fetch device details
try {
    $stmt = $pdo->prepare("SELECT pnode_name, pnode_ip, username FROM devices WHERE id = :device_id");
    $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
    $stmt->execute();
    $device = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$device) {
        $error = "Device not found.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_details_access_failed', $error);
    } elseif ($device['username'] !== $_SESSION['username'] && !$_SESSION['admin']) {
        $error = "Unauthorized access to device.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_details_access_failed', $error);
    } else {
        // Fetch and parse JSON summary
        if (!filter_var($device['pnode_ip'], FILTER_VALIDATE_IP)) {
            $summary_data = ['error' => 'Invalid IP address.'];
        } else {
            $raw_summary = fetchDeviceSummary($device['pnode_ip']);
            $summary_data = parseDeviceSummary($raw_summary, $device['pnode_ip']);
        }
    }
} catch (PDOException $e) {
    $error = "Error fetching device: " . $e->getMessage();
    error_log("PDOException in device fetch: " . $e->getMessage());
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_details_access_failed', $error);
}

// Fetch total log count
try {
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $offset = ($page - 1) * $limit;

    $pnode_name = $device['pnode_name'] ?? '';
    $pnode_ip = $device['pnode_ip'] ?? '';
    $device_name_pattern = "%Device: $pnode_name%";
    $ip_pattern = "%IP: $pnode_ip%";

    // Debug: Log patterns
    error_log("Device ID: $device_id, Name: $pnode_name, IP: $pnode_ip, Patterns: device_name_pattern='$device_name_pattern', ip_pattern='$ip_pattern'");

    $where_conditions = [
        "action IN ('device_status_check_success', 'device_status_check_failed', 'device_register_success', 'device_edit_success', 'device_delete_success')",
        "(ui.details LIKE :device_name_pattern OR ui.details LIKE :ip_pattern)"
    ];
    $params = [
        ':device_name_pattern' => $device_name_pattern,
        ':ip_pattern' => $ip_pattern
    ];
    if (!$_SESSION['admin']) {
        $where_conditions[] = "ui.user_id = :user_id";
        $params[':user_id'] = $_SESSION['user_id'];
    }

    $count_sql = "
        SELECT COUNT(*) 
        FROM user_interactions ui
        WHERE " . implode(" AND ", $where_conditions);

    $stmt = $pdo->prepare($count_sql);
    foreach ($params as $key => $value) {
        $type = ($key === ':user_id') ? PDO::PARAM_INT : PDO::PARAM_STR;
        $stmt->bindValue($key, $value, $type);
    }

    // Debug: Log emulated query
    $emulated_count_query = "SELECT COUNT(*) 
                            FROM user_interactions ui
                            WHERE " . str_replace(
        [':device_name_pattern', ':ip_pattern', ':user_id'],
        ["'$device_name_pattern'", "'$ip_pattern'", $_SESSION['admin'] ? '' : $_SESSION['user_id']],
        implode(" AND ", $where_conditions)
    );
    error_log("Emulated count query: $emulated_count_query");

    $stmt->execute();
    $total_logs = $stmt->fetchColumn();
    $total_pages = ceil($total_logs / $limit);
} catch (PDOException $e) {
    $error = "Error fetching log count: " . $e->getMessage();
    error_log("PDOException in log count: " . $e->getMessage());
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_logs_count_failed', $error);
}

// Fetch paginated logs
try {
    $where_conditions = [
        "action IN ('device_status_check_success', 'device_status_check_failed', 'device_register_success', 'device_edit_success', 'device_delete_success')",
        "(ui.details LIKE :device_name_pattern OR ui.details LIKE :ip_pattern)"
    ];
    $params = [
        ':device_name_pattern' => $device_name_pattern,
        ':ip_pattern' => $ip_pattern,
        ':limit' => (int)$limit,
        ':offset' => (int)$offset
    ];
    if (!$_SESSION['admin']) {
        $where_conditions[] = "ui.user_id = :user_id";
        $params[':user_id'] = $_SESSION['user_id'];
    }

    $sql = "
        SELECT ui.action, ui.timestamp, ui.details 
        FROM user_interactions ui
        WHERE " . implode(" AND ", $where_conditions) . "
        ORDER BY ui.timestamp DESC 
        LIMIT :limit OFFSET :offset
    ";

    $stmt = $pdo->prepare($sql);
    foreach ($params as $key => $value) {
        $type = (in_array($key, [':user_id', ':limit', ':offset'])) ? PDO::PARAM_INT : PDO::PARAM_STR;
        $stmt->bindValue($key, $value, $type);
    }

    // Debug: Log emulated query
    $emulated_query = "SELECT ui.action, ui.timestamp, ui.details 
                       FROM user_interactions ui
                       WHERE " . str_replace(
        [':device_name_pattern', ':ip_pattern', ':user_id'],
        ["'$device_name_pattern'", "'$ip_pattern'", $_SESSION['admin'] ? '' : $_SESSION['user_id']],
        implode(" AND ", $where_conditions)
    ) . "
                       ORDER BY ui.timestamp DESC 
                       LIMIT $limit OFFSET $offset";
    error_log("Emulated log query: $emulated_query");

    $stmt->execute();
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Error fetching device logs: " . $e->getMessage();
    error_log("PDOException in log fetch: " . $e->getMessage());
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_logs_fetch_failed', $error);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Details</title>
    <link rel="icon" type="image/x-icon" href="images/favicon.ico">
    <link rel="icon" type="image/png" sizes="32x32" href="images/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="images/favicon-16x16.png">    
    <link rel="stylesheet" href="style.css">
    <style>
        .summary-container { margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; background: #f9f9f9; }
        .device-info, .logs { margin-bottom: 20px; }
        .log-table { width: 100%; border-collapse: collapse; }
        .log-table th, .log-table td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        .pagination { margin-top: 10px; }
        .pagination a, .pagination select { margin-right: 5px; }
    </style>
</head>
<body>
    <div class="console-container">
        <!-- Top Bar Header -->
        <div class="top-bar">
            <h1>Network Management Console</h1>
            <div class="user-info">
                <span>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
                <a href="logout.php" class="logout-btn">Logout</a>
            </div>
        </div>
        <!-- Main Content -->
        <div class="main-content">
            <!-- Left Menu -->
            <div class="menu-column">
                <ul>
                    <li><button class="menu-button" onclick="window.location.href='dashboard.php'">Dashboard</button></li>
                    <li><button class="menu-button" onclick="window.location.href='devices.php'">Manage Devices</button></li>
                    <li><button class="menu-button active" onclick="window.location.href='device_logs.php'">Device Logs</button></li>
                    <?php if ($_SESSION['admin']): ?>
                        <li class="admin-section">
                            <strong>Admin</strong>
                            <ul>
                                <li><button class="menu-button admin-button" onclick="window.location.href='admin_users.php'">Users</button></li>
                                <li><button class="menu-button admin-button" onclick="window.location.href='admin_devices.php'">Devices</button></li>
                            </ul>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
            <!-- Right Panel -->
            <div class="info-panel">
                <h2>Device Details</h2>
                <?php if (isset($error)): ?>
                    <p class="error"><?php echo htmlspecialchars($error); ?></p>
                <?php elseif ($device): ?>
                    <!-- Device Information -->
                    <div class="device-info">
                        <h3>Device Information</h3>
                        <p><strong>Node Name:</strong> <?php echo htmlspecialchars($device['pnode_name']); ?></p>
                        <p><strong>IP Address:</strong> <?php echo htmlspecialchars($device['pnode_ip']); ?></p>
                        <p><strong>Owner:</strong> <?php echo htmlspecialchars($device['username']); ?></p>
                    </div>

                    <!-- Device Summary -->
                    <div class="summary-container">
                        <h3>Device Summary (IP: <?php echo htmlspecialchars($device['pnode_ip']); ?>)</h3>
                        <?php if ($summary_data['error']): ?>
                            <p class="error"><?php echo htmlspecialchars($summary_data['error']); ?></p>
                        <?php else: ?>
                            <ul>
                                <?php if ($summary_data['uptime'] !== null): ?>
                                    <li><strong>Uptime:</strong> <?php echo htmlspecialchars($summary_data['uptime']); ?></li>
                                <?php endif; ?>
                                <?php if ($summary_data['cpu_usage'] !== null): ?>
                                    <li><strong>CPU Usage:</strong> <?php echo htmlspecialchars($summary_data['cpu_usage']); ?></li>
                                <?php endif; ?>
                                <?php if ($summary_data['memory_usage'] !== null): ?>
                                    <li><strong>Memory Usage:</strong> <?php echo htmlspecialchars($summary_data['memory_usage']); ?></li>
                                <?php endif; ?>
                            </ul>
                        <?php endif; ?>
                    </div>

                    <!-- Recent Logs -->
                    <div class="logs">
                        <h3>Recent Logs</h3>
                        <?php if (empty($logs)): ?>
                            <p>No logs available for this device.</p>
                        <?php else: ?>
                            <table class="log-table">
                                <thead>
                                    <tr>
                                        <th>Action</th>
                                        <th>Timestamp</th>
                                        <th>Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($logs as $log): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($log['action']); ?></td>
                                            <td><?php echo htmlspecialchars($log['timestamp']); ?></td>
                                            <td><?php echo htmlspecialchars($log['details'] ?? 'N/A'); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                            <!-- Pagination -->
                            <?php if ($total_pages > 1): ?>
                                <div class="pagination">
                                    <?php if ($page > 1): ?>
                                        <a href="?device_id=<?php echo $device_id; ?>&page=1&limit=<?php echo $limit; ?>">First</a>
                                        <a href="?device_id=<?php echo $device_id; ?>&page=<?php echo $page - 1; ?>&limit=<?php echo $limit; ?>">Previous</a>
                                    <?php endif; ?>
                                    <select onchange="window.location.href='?device_id=<?php echo $device_id; ?>&page=' + this.value + '&limit=<?php echo $limit; ?>'">
                                        <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                                            <option value="<?php echo $i; ?>" <?php echo $i === $page ? 'selected' : ''; ?>><?php echo $i; ?></option>
                                        <?php endfor; ?>
                                    </select>
                                    <span>of <?php echo $total_pages; ?></span>
                                    <?php if ($page < $total_pages): ?>
                                        <a href="?device_id=<?php echo $device_id; ?>&page=<?php echo $page + 1; ?>&limit=<?php echo $limit; ?>">Next</a>
                                        <a href="?device_id=<?php echo $device_id; ?>&page=<?php echo $total_pages; ?>&limit=<?php echo $limit; ?>">Last</a>
                                    <?php endif; ?>
                                    <select onchange="window.location.href='?device_id=<?php echo $device_id; ?>&page=1&limit=' + this.value">
                                        <?php foreach ([5, 10, 20, 50] as $l): ?>
                                            <option value="<?php echo $l; ?>" <?php echo $l === $limit ? 'selected' : ''; ?>><?php echo $l; ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>