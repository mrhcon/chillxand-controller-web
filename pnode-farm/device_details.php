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
    $stmt = $pdo->prepare("SELECT pnode_name, pnode_ip, username, created FROM devices WHERE id = :device_id");
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
        $device_statuses = getLatestDeviceStatuses($pdo, [$device_id]);
        $current_status = $device_statuses[$device_id] ?? [
            'status' => 'Not Initialized',
            'check_time' => null,
            'response_time' => null,
            'consecutive_failures' => 0,
            'health_status' => null,
            'atlas_registered' => null,
            'pod_status' => null,
            'xandminer_status' => null,
            'xandminerd_status' => null,
            'cpu_load_avg' => null,
            'memory_percent' => null,
            'memory_total_bytes' => null,
            'memory_used_bytes' => null,
            'server_ip' => null,
            'server_hostname' => null,
            'chillxand_version' => null,
            'pod_version' => null,
            'xandminer_version' => null,
            'xandminerd_version' => null,
            'error_message' => 'Device has not been checked yet'
        ];
        $device_summary = parseCachedDeviceHealth($current_status);
    }
} catch (PDOException $e) {
    $error = "Error fetching device: " . $e->getMessage();
    error_log("PDOException in device fetch: " . $e->getMessage());
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_details_access_failed', $error);
}

// Pagination for device status logs
$device_logs_page = isset($_GET['device_logs_page']) ? (int)$_GET['device_logs_page'] : 1;
$device_logs_limit = isset($_GET['device_logs_limit']) ? (int)$_GET['device_logs_limit'] : 10;
$device_logs_offset = ($device_logs_page - 1) * $device_logs_limit;

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
               server_ip, server_hostname, chillxand_version,
               pod_version, xandminer_version, xandminerd_version
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
                    <li><button class="menu-button" onclick="window.location.href='user_dashboard.php'">Dashboard</button></li>
                    <?php if ($_SESSION['admin']): ?>
                        <li class="admin-section">
                            <strong>Admin</strong>
                            <ul>
                                <li><button class="menu-button admin-button" onclick="window.location.href='admin_users.php'">Manage Users</button></li>
                                <li><button class="menu-button admin-button" onclick="window.location.href='admin_devices.php'">Manage Devices</button></li>
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
                                    <p><strong>Registration Date:</strong> <?php echo htmlspecialchars($device['created']); ?></p>
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
                                            <span class="health-status-indicator status-<?php echo $current_status['health_status'] == 'pass' ? 'online' : 'offline'; ?>">
                                                <?php echo ucfirst($current_status['health_status'] ?? 'unknown'); ?>
                                            </span>
                                        </li>
                                        <li><strong>Atlas Registered:</strong> 
                                            <span class="health-status-indicator status-<?php echo $current_status['atlas_registered'] ? 'online' : 'offline'; ?>">
                                                <?php echo $current_status['atlas_registered'] ? 'Yes' : 'No'; ?>
                                            </span>
                                        </li>
                                        <li><strong>Pod:</strong> 
                                            <span class="health-status-indicator status-<?php echo $current_status['pod_status'] == 'active' ? 'online' : 'offline'; ?>">
                                                <?php echo ucfirst($current_status['pod_status'] ?? 'unknown'); ?>
                                            </span>
                                        </li>
                                        <li><strong>XandMiner:</strong> 
                                            <span class="health-status-indicator status-<?php echo $current_status['xandminer_status'] == 'active' ? 'online' : 'offline'; ?>">
                                                <?php echo ucfirst($current_status['xandminer_status'] ?? 'unknown'); ?>
                                            </span>
                                        </li>
                                        <li><strong>XandMinerD:</strong> 
                                            <span class="health-status-indicator status-<?php echo $current_status['xandminerd_status'] == 'active' ? 'online' : 'offline'; ?>">
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
                                        <li><strong>ChillXand Controller:</strong> <span class="version-info"><?php echo htmlspecialchars($current_status['chillxand_version'] ?? 'N/A'); ?></span></li>
                                        <li><strong>Pod:</strong> <span class="version-info"><?php echo htmlspecialchars($current_status['pod_version'] ?? 'N/A'); ?></span></li>
                                        <li><strong>XandMiner:</strong> <span class="version-info"><?php echo htmlspecialchars($current_status['xandminer_version'] ?? 'N/A'); ?></span></li>
                                        <li><strong>XandMinerD:</strong> <span class="version-info"><?php echo htmlspecialchars($current_status['xandminerd_version'] ?? 'N/A'); ?></span></li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>

                    <!-- Device Status Logs -->
                    <div class="logs">
                        <h3>Device Status Logs (<?php echo $total_device_logs; ?>)</h3>
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
                                                if ($log['pod_version']) $versions[] = 'Pod: ' . htmlspecialchars($log['pod_version']);
                                                if ($log['xandminer_version']) $versions[] = 'XM: ' . htmlspecialchars($log['xandminer_version']);
                                                if ($log['xandminerd_version']) $versions[] = 'XMD: ' . htmlspecialchars($log['xandminerd_version']);
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
                                        <a href="?device_id=<?php echo $device_id; ?>&device_logs_page=1&device_logs_limit=<?php echo $device_logs_limit; ?>">First</a>
                                        <a href="?device_id=<?php echo $device_id; ?>&device_logs_page=<?php echo $device_logs_page - 1; ?>&device_logs_limit=<?php echo $device_logs_limit; ?>">Previous</a>
                                    <?php endif; ?>
                                    <select onchange="window.location.href='?device_id=<?php echo $device_id; ?>&device_logs_page=' + this.value + '&device_logs_limit=<?php echo $device_logs_limit; ?>'">
                                        <?php for ($i = 1; $i <= $total_device_pages; $i++): ?>
                                            <option value="<?php echo $i; ?>" <?php echo $i === $device_logs_page ? 'selected' : ''; ?>><?php echo $i; ?></option>
                                        <?php endfor; ?>
                                    </select>
                                    <span>of <?php echo $total_device_pages; ?></span>
                                    <?php if ($device_logs_page < $total_device_pages): ?>
                                        <a href="?device_id=<?php echo $device_id; ?>&device_logs_page=<?php echo $device_logs_page + 1; ?>&device_logs_limit=<?php echo $device_logs_limit; ?>">Next</a>
                                        <a href="?device_id=<?php echo $device_id; ?>&device_logs_page=<?php echo $total_device_pages; ?>&device_logs_limit=<?php echo $device_logs_limit; ?>">Last</a>
                                    <?php endif; ?>
                                    <select onchange="window.location.href='?device_id=<?php echo $device_id; ?>&device_logs_page=1&device_logs_limit=' + this.value">
                                        <?php foreach ([5, 10, 20, 50] as $l): ?>
                                            <option value="<?php echo $l; ?>" <?php echo $l === $device_logs_limit ? 'selected' : ''; ?>><?php echo $l; ?></option>
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

    <script>
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