<?php
session_start();
require_once 'db_connect.php';
require_once 'functions.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Fetch user details
try {
    $stmt = $pdo->prepare("SELECT username, email, first_name, last_name, country, admin FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    $_SESSION['admin'] = $user['admin']; // Store admin status in session
} catch (PDOException $e) {
    $error = "Error fetching user details: " . $e->getMessage();
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'dashboard_access_failed', $error);
}

// Fetch last login time
try {
    $stmt = $pdo->prepare("
        SELECT timestamp 
        FROM user_interactions 
        WHERE user_id = ? AND action = 'login_success' 
        ORDER BY timestamp DESC 
        LIMIT 1 OFFSET 1
    ");
    $stmt->execute([$_SESSION['user_id']]);
    $last_login = $stmt->fetchColumn();
    $last_login_display = $last_login ? htmlspecialchars($last_login) : "No previous login recorded";
} catch (PDOException $e) {
    $error = "Error fetching last login: " . $e->getMessage();
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'last_login_fetch_failed', $error);
}

// Fetch user's devices with enhanced status and order by node name
try {
    $stmt = $pdo->prepare("
        SELECT d.id, d.pnode_name, d.pnode_ip, d.registration_date
        FROM devices d
        WHERE d.username = ?
        ORDER BY d.pnode_name ASC
    ");
    $stmt->execute([$_SESSION['username']]);
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get latest statuses for all devices at once (super efficient!)
    $device_ids = array_column($devices, 'id');
    $cached_statuses = getLatestDeviceStatuses($pdo, $device_ids);
    
    // Add cached status and health data to each device
    $updated_devices = [];
    foreach ($devices as $device) {
        $device_id = $device['id'];
        $cached_status = $cached_statuses[$device_id] ?? [
            'status' => 'Not Initialized',
            'is_stale' => true,
            'error_message' => 'Device has not been checked yet'
        ];
        
        // Add status from cache
        $device['status'] = $cached_status['status'];
        $device['status_age'] = $cached_status['age_minutes'];
        $device['status_stale'] = $cached_status['is_stale'];
        $device['last_check'] = $cached_status['check_time'];
        $device['response_time'] = $cached_status['response_time'];
        $device['consecutive_failures'] = $cached_status['consecutive_failures'];
        $device['health_status'] = $cached_status['health_status'];
        
        // Determine overall status (connectivity + health)
        $overall_status = 'Unknown';
        if ($device['status'] === 'Online') {
            if ($device['health_status'] === 'pass') {
                $overall_status = 'Healthy';
            } elseif ($device['health_status'] === 'fail') {
                $overall_status = 'Online (Issues)';
            } else {
                $overall_status = 'Online';
            }
        } elseif ($device['status'] === 'Offline') {
            $overall_status = 'Offline';
        } else {
            $overall_status = $device['status'];
        }
        $device['overall_status'] = $overall_status;
        
        // Get last update time from user_interactions for display compatibility
        $device_name_pattern = "%Device: {$device['pnode_name']}%";
        $ip_pattern = "%IP: {$device['pnode_ip']}%";
        $stmt2 = $pdo->prepare("
            SELECT MAX(timestamp) as last_update
            FROM user_interactions 
            WHERE user_id = ? 
            AND action IN ('device_status_check_success', 'device_status_check_failed')
            AND (details LIKE ? OR details LIKE ?)
        ");
        $stmt2->execute([$_SESSION['user_id'], $device_name_pattern, $ip_pattern]);
        $last_update = $stmt2->fetchColumn();
        $device['last_update'] = $last_update ?: $device['last_check'];
        
        $updated_devices[] = $device;
    }
    $devices = $updated_devices;
    
} catch (PDOException $e) {
    $error = "Error fetching devices: " . $e->getMessage();
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_fetch_failed', $error);
}

// Log dashboard access
logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'dashboard_access');
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link rel="stylesheet" href="style.css">
    <style>
        .status-healthy { background-color: #28a745; }
        .status-online-issues { background-color: #ffc107; color: #212529; }
        .status-not-initialized { background-color: #6c757d; }
        .device-status-details { font-size: 11px; color: #666; margin-top: 3px; }
        .status-age { font-size: 10px; color: #666; }
        .status-stale { color: #ff6600; }
        .status-fresh { color: #006600; }
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
            	<img src="ChillXand-logo.png">
                <ul>
                    <li><button class="menu-button active" onclick="window.location.href='dashboard.php'">Dashboard</button></li>
                    <li><button class="menu-button" onclick="window.location.href='devices.php'">Manage Devices</button></li>
                    <li><button class="menu-button" onclick="window.location.href='device_logs.php'">Device Logs</button></li>
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
                <h2>Welcome, <?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name']); ?>!</h2>
                <p>Last Login: <?php echo $last_login_display; ?></p>
                <h3>Your Details:</h3>
                <p><strong>Username:</strong> <?php echo htmlspecialchars($user['username']); ?></p>
                <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?></p>
                <p><strong>Country:</strong> <?php echo htmlspecialchars($user['country']); ?></p>
                <?php if (isset($error)): ?>
                    <p class="error"><?php echo htmlspecialchars($error); ?></p>
                <?php endif; ?>
                <h3>Your Devices:</h3>
                <?php if (empty($devices)): ?>
                    <p>No devices registered.</p>
                <?php else: ?>
                    <table class="device-table">
                        <thead>
                            <tr>
                                <th>Node Name</th>
                                <th>IP Address</th>
                                <th>Registration Date</th>
                                <th>Overall Status</th>
                                <th>Connectivity</th>
                                <th>Health Status</th>
                                <th>Last Update</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($devices as $device): ?>
                                <tr>
                                    <td><a href="device_details.php?device_id=<?php echo $device['id']; ?>"><?php echo htmlspecialchars($device['pnode_name']); ?></a></td>
                                    <td><?php echo htmlspecialchars($device['pnode_ip']); ?></td>
                                    <td><?php echo htmlspecialchars($device['registration_date']); ?></td>
                                    <td>
                                        <span class="status-btn status-<?php echo strtolower(str_replace(['(', ')', ' '], ['-', '', '-'], $device['overall_status'])); ?>">
                                            <?php echo htmlspecialchars($device['overall_status']); ?>
                                        </span>
                                        <div class="status-age <?php echo $device['status_stale'] ? 'status-stale' : 'status-fresh'; ?>">
                                            <?php if ($device['last_check']): ?>
                                                <?php echo $device['status_age'] ? round($device['status_age']) . 'm ago' : 'Just now'; ?>
                                            <?php else: ?>
                                                Never checked
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="status-btn status-<?php echo strtolower($device['status']); ?>">
                                            <?php echo htmlspecialchars($device['status']); ?>
                                        </span>
                                        <?php if ($device['response_time']): ?>
                                            <div class="device-status-details">Response: <?php echo round($device['response_time'] * 1000, 1); ?>ms</div>
                                        <?php endif; ?>
                                        <?php if ($device['consecutive_failures'] > 0): ?>
                                            <div class="device-status-details" style="color: #dc3545;">Failures: <?php echo $device['consecutive_failures']; ?></div>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($device['health_status']): ?>
                                            <span class="status-btn status-<?php echo $device['health_status'] == 'pass' ? 'online' : 'offline'; ?>">
                                                <?php echo ucfirst($device['health_status']); ?>
                                            </span>
                                        <?php else: ?>
                                            <span class="status-btn status-unknown">Unknown</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($device['last_update']): ?>
                                            <?php echo htmlspecialchars($device['last_update']); ?>
                                        <?php else: ?>
                                            <span style="font-style: italic; color: #999;">N/A</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
                
                <div style="margin-top: 20px; padding: 10px; background-color: #e9ecef; border-radius: 4px;">
                    <h4>Status Legend</h4>
                    <div style="display: flex; gap: 15px; flex-wrap: wrap; font-size: 12px;">
                        <span><span class="status-btn status-healthy" style="padding: 2px 6px;">Healthy</span> = Online + Health Pass</span>
                        <span><span class="status-btn status-online-issues" style="padding: 2px 6px;">Online (Issues)</span> = Online + Health Fail</span>
                        <span><span class="status-btn status-online" style="padding: 2px 6px;">Online</span> = Connected, Health Unknown</span>
                        <span><span class="status-btn status-offline" style="padding: 2px 6px;">Offline</span> = Not Reachable</span>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>