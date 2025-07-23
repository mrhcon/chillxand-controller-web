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
    $stmt = $pdo->prepare("SELECT pnode_name, pnode_ip, username, registration_date FROM devices WHERE id = :device_id");
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
        // Get current device status
        $current_status = getLatestDeviceStatus($pdo, $device_id);
        $device_summary = parseCachedDeviceHealth($current_status);
    }
} catch (PDOException $e) {
    $error = "Error fetching device: " . $e->getMessage();
    error_log("PDOException in device fetch: " . $e->getMessage());
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_details_access_failed', $error);
}

// Pagination for user interaction logs
$user_logs_page = isset($_GET['user_logs_page']) ? (int)$_GET['user_logs_page'] : 1;
$user_logs_limit = isset($_GET['user_logs_limit']) ? (int)$_GET['user_logs_limit'] : 10;
$user_logs_offset = ($user_logs_page - 1) * $user_logs_limit;

// Pagination for device status logs
$device_logs_page = isset($_GET['device_logs_page']) ? (int)$_GET['device_logs_page'] : 1;
$device_logs_limit = isset($_GET['device_logs_limit']) ? (int)$_GET['device_logs_limit'] : 10;
$device_logs_offset = ($device_logs_page - 1) * $device_logs_limit;

// Fetch total user interaction log count
try {
    $pnode_name = $device['pnode_name'] ?? '';
    $pnode_ip = $device['pnode_ip'] ?? '';
    
    // Get ALL actions related to this device, not just specific ones
    $count_sql = "
        SELECT COUNT(*) 
        FROM user_interactions ui
        WHERE (ui.details LIKE :device_name_pattern OR ui.details LIKE :ip_pattern)
    ";
    
    if (!$_SESSION['admin']) {
        $count_sql .= " AND ui.user_id = :user_id";
    }

    $stmt = $pdo->prepare($count_sql);
    $stmt->bindValue(':device_name_pattern', "%{$pnode_name}%", PDO::PARAM_STR);
    $stmt->bindValue(':ip_pattern', "%{$pnode_ip}%", PDO::PARAM_STR);
    if (!$_SESSION['admin']) {
        $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    }
    $stmt->execute();
    $total_user_logs = $stmt->fetchColumn();
    $total_user_pages = ceil($total_user_logs / $user_logs_limit);
} catch (PDOException $e) {
    $error = "Error fetching user log count: " . $e->getMessage();
    error_log("PDOException in user log count: " . $e->getMessage());
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_logs_count_failed', $error);
}

// Fetch paginated user interaction logs (ALL actions)
try {
    $sql = "
        SELECT ui.action, ui.timestamp, ui.details, ui.username
        FROM user_interactions ui
        WHERE (ui.details LIKE :device_name_pattern OR ui.details LIKE :ip_pattern)
    ";
    
    if (!$_SESSION['admin']) {
        $sql .= " AND ui.user_id = :user_id";
    }
    
    $sql .= " ORDER BY ui.timestamp DESC LIMIT :limit OFFSET :offset";

    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(':device_name_pattern', "%{$pnode_name}%", PDO::PARAM_STR);
    $stmt->bindValue(':ip_pattern', "%{$pnode_ip}%", PDO::PARAM_STR);
    $stmt->bindValue(':limit', (int)$user_logs_limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', (int)$user_logs_offset, PDO::PARAM_INT);
    if (!$_SESSION['admin']) {
        $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    }
    $stmt->execute();
    $user_logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Error fetching user logs: " . $e->getMessage();
    error_log("PDOException in user log fetch: " . $e->getMessage());
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_logs_fetch_failed', $error);
}

// Fetch total device status log count
try {
    $count_sql = "SELECT COUNT(*) FROM device_status_log WHERE device_id = :device_id";
    $stmt = $pdo->prepare($count_sql);
    $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
    $stmt->execute();
    $total_device_logs = $stmt->fetchColumn();
    $total_device_pages = ceil($total_device_logs / $device_logs_limit);
} catch (PDOException $e) {
    $error = "Error fetching device status log count: " . $e->getMessage();
    error_log("PDOException in device status log count: " . $e->getMessage());
}

// Fetch paginated device status logs
try {
    $sql = "
        SELECT status, check_time, response_time, check_method, error_message, consecutive_failures,
               health_status, atlas_registered, pod_status, xandminer_status, xandminerd_status,
               cpu_load_avg, memory_percent, memory_total_bytes, memory_used_bytes,
               server_ip, server_hostname, chillxand_version, node_version
        FROM device_status_log 
        WHERE device_id = :device_id
        ORDER BY check_time DESC 
        LIMIT :limit OFFSET :offset
    ";
    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
    $stmt->bindValue(':limit', (int)$device_logs_limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', (int)$device_logs_offset, PDO::PARAM_INT);
    $stmt->execute();
    $device_status_logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Error fetching device status logs: " . $e->getMessage();
    error_log("PDOException in device status log fetch: " . $e->getMessage());
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
        .summary-container { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; background: #f9f9f9; border-radius: 5px; }
        .device-info, .logs { margin-bottom: 25px; }
        .log-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .log-table th, .log-table td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 12px; }
        .log-table th { background-color: #f8f9fa; font-weight: bold; }
        .pagination { margin: 15px 0; display: flex; align-items: center; gap: 10px; }
        .pagination a, .pagination select { padding: 5px 10px; text-decoration: none; border: 1px solid #ddd; border-radius: 3px; }
        .pagination a:hover { background-color: #f8f9fa; }
        .pagination a.disabled { color: #ccc; pointer-events: none; }
        .status-online { color: #28a745; font-weight: bold; }
        .status-offline { color: #dc3545; font-weight: bold; }
        .status-error { color: #ffc107; font-weight: bold; }
        .health-pass { color: #28a745; }
        .health-fail { color: #dc3545; }
        .atlas-yes { color: #28a745; }
        .atlas-no { color: #dc3545; }
        .service-active { color: #28a745; }
        .service-inactive { color: #dc3545; }
        .metrics { font-size: 11px; color: #666; }
        .error-msg { color: #dc3545; font-size: 11px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; }
        .tab-buttons { margin-bottom: 15px; }
        .tab-button { padding: 8px 16px; margin-right: 5px; border: 1px solid #ddd; background: #f8f9fa; cursor: pointer; border-radius: 3px 3px 0 0; }
        .tab-button.active { background: #007bff; color: white; border-bottom: 1px solid #007bff; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .version-info { font-family: 'Courier New', monospace; font-size: 11px; }
    </style>
</head>
<body>
    <div class="console-container">
        <!-- Top Bar Header -->
        <div class="top-bar">
            <h1>ChillXand - pNode Management Console</h1>
            <div class="user-info">
                <span>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
                <a href="logout.php" class="logout-btn">Logout</a>
            </div>
        </div>
        <!-- Main Content -->
        <div class="main-content">
            <!-- Left Menu -->
            <div class="menu-column">
                <img src="images/logo.png">
                <ul>
                    <li><button class="menu-button" onclick="window.location.href='updated_dashboard.php'">Dashboard</button></li>
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
                        <div class="summary-container">
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                                <div>
                                    <p><strong>Node Name:</strong> <?php echo htmlspecialchars($device['pnode_name']); ?></p>
                                    <p><strong>IP Address:</strong> <?php echo htmlspecialchars($device['pnode_ip']); ?></p>
                                    <p><strong>Owner:</strong> <?php echo htmlspecialchars($device['username']); ?></p>
                                    <p><strong>Registration Date:</strong> <?php echo htmlspecialchars($device['registration_date']); ?></p>
                                </div>
                                <div>
                                    <p><strong>Current Status:</strong> 
                                        <span class="status-btn status-<?php echo strtolower(str_replace(' ', '-', $current_status['status'])); ?>">
                                            <?php echo htmlspecialchars($current_status['status']); ?>
                                        </span>
                                    </p>
                                    <?php if ($current_status['check_time']): ?>
                                        <p><strong>Last Checked:</strong> <?php echo htmlspecialchars($current_status['check_time']); ?></p>
                                        <p><strong>Response Time:</strong> <?php echo $current_status['response_time'] ? round($current_status['response_time'] * 1000, 1) . 'ms' : 'N/A'; ?></p>
                                    <?php endif; ?>
                                    <?php if ($current_status['consecutive_failures'] > 0): ?>
                                        <p><strong>Consecutive Failures:</strong> <span style="color: #dc3545;"><?php echo $current_status['consecutive_failures']; ?></span></p>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Current Health Status -->
                    <?php if ($current_status['status'] !== 'Not Initialized'): ?>
                    <div class="device-info">
                        <h3>Current Health Status</h3>
                        <div class="summary-container">
                            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px;">
                                <div>
                                    <h4>Service Status</h4>
                                    <ul style="list-style: none; padding: 0;">
                                        <li><strong>Overall Health:</strong> 
                                            <span class="status-btn status-<?php echo $current_status['health_status'] == 'pass' ? 'online' : 'offline'; ?>" style="padding: 2px 8px; font-size: 10px;">
                                                <?php echo ucfirst($current_status['health_status'] ?? 'unknown'); ?>
                                            </span>
                                        </li>
                                        <li><strong>Atlas Registered:</strong> 
                                            <span class="status-btn status-<?php echo $current_status['atlas_registered'] ? 'online' : 'offline'; ?>" style="padding: 2px 8px; font-size: 10px;">
                                                <?php echo $current_status['atlas_registered'] ? 'Yes' : 'No'; ?>
                                            </span>
                                        </li>
                                        <li><strong>Pod:</strong> 
                                            <span class="status-btn status-<?php echo $current_status['pod_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 2px 8px; font-size: 10px;">
                                                <?php echo ucfirst($current_status['pod_status'] ?? 'unknown'); ?>
                                            </span>
                                        </li>
                                        <li><strong>XandMiner:</strong> 
                                            <span class="status-btn status-<?php echo $current_status['xandminer_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 2px 8px; font-size: 10px;">
                                                <?php echo ucfirst($current_status['xandminer_status'] ?? 'unknown'); ?>
                                            </span>
                                        </li>
                                        <li><strong>XandMinerD:</strong> 
                                            <span class="status-btn status-<?php echo $current_status['xandminerd_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 2px 8px; font-size: 10px;">
                                                <?php echo ucfirst($current_status['xandminerd_status'] ?? 'unknown'); ?>
                                            </span>
                                        </li>
                                    </ul>
                                </div>
                                <div>
                                    <h4>System Metrics</h4>
                                    <ul style="list-style: none; padding: 0;">
                                        <?php if ($current_status['cpu_load_avg'] !== null): ?>
                                            <li><strong>CPU Load:</strong> <?php echo number_format($current_status['cpu_load_avg'], 2); ?></li>
                                        <?php endif; ?>
                                        <?php if ($current_status['memory_percent'] !== null): ?>
                                            <li><strong>Memory:</strong> <?php echo number_format($current_status['memory_percent'], 1); ?>%</li>
                                        <?php endif; ?>
                                        <?php if ($current_status['memory_total_bytes']): ?>
                                            <li><strong>Total Memory:</strong> <?php echo number_format($current_status['memory_total_bytes'] / 1024 / 1024 / 1024, 1); ?> GB</li>
                                        <?php endif; ?>
                                        <?php if ($current_status['server_hostname']): ?>
                                            <li><strong>Hostname:</strong> <?php echo htmlspecialchars($current_status['server_hostname']); ?></li>
                                        <?php endif; ?>
                                        <?php if ($current_status['server_ip']): ?>
                                            <li><strong>Server IP:</strong> <?php echo htmlspecialchars($current_status['server_ip']); ?></li>
                                        <?php endif; ?>
                                    </ul>
                                </div>
                                <div>
                                    <h4>Version Information</h4>
                                    <ul style="list-style: none; padding: 0;">
                                        <?php if ($current_status['chillxand_version']): ?>
                                            <li><strong>ChillXand:</strong> <span class="version-info"><?php echo htmlspecialchars($current_status['chillxand_version']); ?></span></li>
                                        <?php endif; ?>
                                        <?php if ($current_status['node_version']): ?>
                                            <li><strong>Node:</strong> <span class="version-info"><?php echo htmlspecialchars($current_status['node_version']); ?></span></li>
                                        <?php endif; ?>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>

                    <!-- Tabbed Logs Section -->
                    <div class="logs">
                        <h3>Device Logs</h3>
                        <div class="tab-buttons">
                            <button class="tab-button active" onclick="showTab('user-actions')">All User Actions (<?php echo $total_user_logs; ?>)</button>
                            <button class="tab-button" onclick="showTab('device-status')">Device Status Logs (<?php echo $total_device_logs; ?>)</button>
                        </div>

                        <!-- User Actions Tab -->
                        <div id="user-actions" class="tab-content active">
                            <?php if (empty($user_logs)): ?>
                                <p>No user action logs available for this device.</p>
                            <?php else: ?>
                                <table class="log-table">
                                    <thead>
                                        <tr>
                                            <th>Action</th>
                                            <th>Timestamp</th>
                                            <th>User</th>
                                            <th>Details</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($user_logs as $log): ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($log['action']); ?></td>
                                                <td><?php echo htmlspecialchars($log['timestamp']); ?></td>
                                                <td><?php echo htmlspecialchars($log['username']); ?></td>
                                                <td><?php echo htmlspecialchars($log['details'] ?? 'N/A'); ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                                <!-- User Actions Pagination -->
                                <?php if ($total_user_pages > 1): ?>
                                    <div class="pagination">
                                        <?php if ($user_logs_page > 1): ?>
                                            <a href="?device_id=<?php echo $device_id; ?>&user_logs_page=1&user_logs_limit=<?php echo $user_logs_limit; ?>&device_logs_page=<?php echo $device_logs_page; ?>&device_logs_limit=<?php echo $device_logs_limit; ?>">First</a>
                                            <a href="?device_id=<?php echo $device_id; ?>&user_logs_page=<?php echo $user_logs_page - 1; ?>&user_logs_limit=<?php echo $user_logs_limit; ?>&device_logs_page=<?php echo $device_logs_page; ?>&device_logs_limit=<?php echo $device_logs_limit; ?>">Previous</a>
                                        <?php endif; ?>
                                        <select onchange="window.location.href='?device_id=<?php echo $device_id; ?>&user_logs_page=' + this.value + '&user_logs_limit=<?php echo $user_logs_limit; ?>&device_logs_page=<?php echo $device_logs_page; ?>&device_logs_limit=<?php echo $device_logs_limit; ?>'">
                                            <?php for ($i = 1; $i <= $total_user_pages; $i++): ?>
                                                <option value="<?php echo $i; ?>" <?php echo $i === $user_logs_page ? 'selected' : ''; ?>><?php echo $i; ?></option>
                                            <?php endfor; ?>
                                        </select>
                                        <span>of <?php echo $total_user_pages; ?></span>
                                        <?php if ($user_logs_page < $total_user_pages): ?>
                                            <a href="?device_id=<?php echo $device_id; ?>&user_logs_page=<?php echo $user_logs_page + 1; ?>&user_logs_limit=<?php echo $user_logs_limit; ?>&device_logs_page=<?php echo $device_logs_page; ?>&device_logs_limit=<?php echo $device_logs_limit; ?>">Next</a>
                                            <a href="?device_id=<?php echo $device_id; ?>&user_logs_page=<?php echo $total_user_pages; ?>&user_logs_limit=<?php echo $user_logs_limit; ?>&device_logs_page=<?php echo $device_logs_page; ?>&device_logs_limit=<?php echo $device_logs_limit; ?>">Last</a>
                                        <?php endif; ?>
                                        <select onchange="window.location.href='?device_id=<?php echo $device_id; ?>&user_logs_page=1&user_logs_limit=' + this.value + '&device_logs_page=<?php echo $device_logs_page; ?>&device_logs_limit=<?php echo $device_logs_limit; ?>'">
                                            <?php foreach ([5, 10, 20, 50] as $l): ?>
                                                <option value="<?php echo $l; ?>" <?php echo $l === $user_logs_limit ? 'selected' : ''; ?>><?php echo $l; ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                <?php endif; ?>
                            <?php endif; ?>
                        </div>

                        <!-- Device Status Logs Tab -->
                        <div id="device-status" class="tab-content">
                            <?php if (empty($device_status_logs)): ?>
                                <p>No device status logs available.</p>
                            <?php else: ?>
                                <table class="log-table">
                                    <thead>
                                        <tr>
                                            <th>Status</th>
                                            <th>Check Time</th>
                                            <th>Response</th>
                                            <th>Method</th>
                                            <th>Health</th>
                                            <th>Atlas</th>
                                            <th>Services</th>
                                            <th>System Metrics</th>
                                            <th>Versions</th>
                                            <th>Errors</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($device_status_logs as $log): ?>
                                            <tr>
                                                <td>
                                                    <span class="status-<?php echo strtolower($log['status']); ?>">
                                                        <?php echo htmlspecialchars($log['status']); ?>
                                                    </span>
                                                    <?php if ($log['consecutive_failures'] > 0): ?>
                                                        <br><small style="color: #dc3545;">Fails: <?php echo $log['consecutive_failures']; ?></small>
                                                    <?php endif; ?>
                                                </td>
                                                <td><?php echo htmlspecialchars($log['check_time']); ?></td>
                                                <td>
                                                    <?php if ($log['response_time']): ?>
                                                        <?php echo round($log['response_time'] * 1000, 1); ?>ms
                                                    <?php else: ?>
                                                        N/A
                                                    <?php endif; ?>
                                                </td>
                                                <td><?php echo htmlspecialchars($log['check_method'] ?? 'N/A'); ?></td>
                                                <td>
                                                    <?php if ($log['health_status']): ?>
                                                        <span class="health-<?php echo $log['health_status']; ?>"><?php echo ucfirst($log['health_status']); ?></span>
                                                    <?php else: ?>
                                                        N/A
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <?php if (isset($log['atlas_registered'])): ?>
                                                        <span class="atlas-<?php echo $log['atlas_registered'] ? 'yes' : 'no'; ?>"><?php echo $log['atlas_registered'] ? 'Yes' : 'No'; ?></span>
                                                    <?php else: ?>
                                                        N/A
                                                    <?php endif; ?>
                                                </td>
                                                <td class="metrics">
                                                    <?php 
                                                    $services = [];
                                                    if ($log['pod_status']) $services[] = 'Pod: <span class="service-' . $log['pod_status'] . '">' . ucfirst($log['pod_status']) . '</span>';
                                                    if ($log['xandminer_status']) $services[] = 'XM: <span class="service-' . $log['xandminer_status'] . '">' . ucfirst($log['xandminer_status']) . '</span>';
                                                    if ($log['xandminerd_status']) $services[] = 'XMD: <span class="service-' . $log['xandminerd_status'] . '">' . ucfirst($log['xandminerd_status']) . '</span>';
                                                    echo $services ? implode('<br>', $services) : 'N/A';
                                                    ?>
                                                </td>
                                                <td class="metrics">
                                                    <?php 
                                                    $metrics = [];
                                                    if ($log['cpu_load_avg'] !== null) $metrics[] = 'CPU: ' . number_format($log['cpu_load_avg'], 2);
                                                    if ($log['memory_percent'] !== null) $metrics[] = 'Mem: ' . number_format($log['memory_percent'], 1) . '%';
                                                    if ($log['server_hostname']) $metrics[] = 'Host: ' . htmlspecialchars($log['server_hostname']);
                                                    echo $metrics ? implode('<br>', $metrics) : 'N/A';
                                                    ?>
                                                </td>
                                                <td class="version-info">
                                                    <?php 
                                                    $versions = [];
                                                    if ($log['chillxand_version']) $versions[] = 'CX: ' . htmlspecialchars($log['chillxand_version']);
                                                    if ($log['node_version']) $versions[] = 'Node: ' . htmlspecialchars($log['node_version']);
                                                    echo $versions ? implode('<br>', $versions) : 'N/A';
                                                    ?>
                                                </td>
                                                <td>
                                                    <?php if ($log['error_message']): ?>
                                                        <span class="error-msg" title="<?php echo htmlspecialchars($log['error_message']); ?>">
                                                            <?php echo htmlspecialchars(strlen($log['error_message']) > 50 ? substr($log['error_message'], 0, 50) . '...' : $log['error_message']); ?>
                                                        </span>
                                                    <?php else: ?>
                                                        None
                                                    <?php endif; ?>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                                <!-- Device Status Logs Pagination -->
                                <?php if ($total_device_pages > 1): ?>
                                    <div class="pagination">
                                        <?php if ($device_logs_page > 1): ?>
                                            <a href="?device_id=<?php echo $device_id; ?>&user_logs_page=<?php echo $user_logs_page; ?>&user_logs_limit=<?php echo $user_logs_limit; ?>&device_logs_page=1&device_logs_limit=<?php echo $device_logs_limit; ?>">First</a>
                                            <a href="?device_id=<?php echo $device_id; ?>&user_logs_page=<?php echo $user_logs_page; ?>&user_logs_limit=<?php echo $user_logs_limit; ?>&device_logs_page=<?php echo $device_logs_page - 1; ?>&device_logs_limit=<?php echo $device_logs_limit; ?>">Previous</a>
                                        <?php endif; ?>
                                        <select onchange="window.location.href='?device_id=<?php echo $device_id; ?>&user_logs_page=<?php echo $user_logs_page; ?>&user_logs_limit=<?php echo $user_logs_limit; ?>&device_logs_page=' + this.value + '&device_logs_limit=<?php echo $device_logs_limit; ?>'">
                                            <?php for ($i = 1; $i <= $total_device_pages; $i++): ?>
                                                <option value="<?php echo $i; ?>" <?php echo $i === $device_logs_page ? 'selected' : ''; ?>><?php echo $i; ?></option>
                                            <?php endfor; ?>
                                        </select>
                                        <span>of <?php echo $total_device_pages; ?></span>
                                        <?php if ($device_logs_page < $total_device_pages): ?>
                                            <a href="?device_id=<?php echo $device_id; ?>&user_logs_page=<?php echo $user_logs_page; ?>&user_logs_limit=<?php echo $user_logs_limit; ?>&device_logs_page=<?php echo $device_logs_page + 1; ?>&device_logs_limit=<?php echo $device_logs_limit; ?>">Next</a>
                                            <a href="?device_id=<?php echo $device_id; ?>&user_logs_page=<?php echo $user_logs_page; ?>&user_logs_limit=<?php echo $user_logs_limit; ?>&device_logs_page=<?php echo $total_device_pages; ?>&device_logs_limit=<?php echo $device_logs_limit; ?>">Last</a>
                                        <?php endif; ?>
                                        <select onchange="window.location.href='?device_id=<?php echo $device_id; ?>&user_logs_page=<?php echo $user_logs_page; ?>&user_logs_limit=<?php echo $user_logs_limit; ?>&device_logs_page=1&device_logs_limit=' + this.value">
                                            <?php foreach ([5, 10, 20, 50] as $l): ?>
                                                <option value="<?php echo $l; ?>" <?php echo $l === $device_logs_limit ? 'selected' : ''; ?>><?php echo $l; ?></option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                <?php endif; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script>
        function showTab(tabName) {
            // Hide all tab contents
            var tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(function(content) {
                content.classList.remove('active');
            });
            
            // Remove active class from all tab buttons
            var tabButtons = document.querySelectorAll('.tab-button');
            tabButtons.forEach(function(button) {
                button.classList.remove('active');
            });
            
            // Show the selected tab content
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to the clicked button
            event.target.classList.add('active');
        }

        // Auto-refresh current status every 30 seconds
        setInterval(function() {
            // Only refresh if we're on the device details page
            if (window.location.pathname.includes('device_details.php')) {
                console.log('Auto-refreshing device status...');
                window.location.reload();
            }
        }, 30000);
    </script>
</body>
</html>