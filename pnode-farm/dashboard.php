<?php
session_start();
require_once 'db_connect.php';
require_once 'functions.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Handle add device
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'add') {
    echo "<div style='background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; margin: 10px 0;'>✅ ADD DEVICE HANDLER REACHED</div>";

    // Check if required POST variables exist
    if (!isset($_POST['pnode_name']) || !isset($_POST['pnode_ip'])) {
        $error = "Missing required form data.";
        echo "<div style='background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; margin: 10px 0;'>❌ MISSING POST DATA</div>";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', 'Missing form data');
    } else {
        echo "<div style='background: #d1ecf1; border: 1px solid #bee5eb; padding: 10px; margin: 10px 0;'>✅ POST DATA EXISTS</div>";

        $pnode_name = trim($_POST['pnode_name']);
        $pnode_ip = trim($_POST['pnode_ip']);

        if (empty($pnode_name) || empty($pnode_ip)) {
            $error = "Please fill in all fields.";
            echo "<div style='background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; margin: 10px 0;'>❌ EMPTY FIELDS</div>";
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', 'Empty fields');
        } elseif (strlen($pnode_name) > 100) {
            $error = "Node name must be 100 characters or less.";
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', 'Invalid node name length');
        } elseif (!filter_var($pnode_ip, FILTER_VALIDATE_IP)) {
            $error = "Invalid IP address.";
            echo "<div style='background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; margin: 10px 0;'>❌ INVALID IP: " . htmlspecialchars($pnode_ip) . "</div>";
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', 'Invalid IP address');
        } else {
            try {
                echo "<div style='background: #d1ecf1; border: 1px solid #bee5eb; padding: 10px; margin: 10px 0;'>✅ VALIDATION PASSED - CHECKING DUPLICATES</div>";

                $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE username = :username AND pnode_name = :pnode_name");
                $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
                $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
                $stmt->execute();
                if ($stmt->fetchColumn() > 0) {
                    $error = "Device name already registered.";
                    echo "<div style='background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; margin: 10px 0;'>❌ DUPLICATE NAME</div>";
                    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', 'Duplicate device name');
                } else {
                    echo "<div style='background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; margin: 10px 0;'>✅ INSERTING DEVICE</div>";

                    // Add device
                    $stmt = $pdo->prepare("INSERT INTO devices (username, pnode_name, pnode_ip, registration_date) VALUES (:username, :pnode_name, :pnode_ip, NOW())");
                    $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
                    $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
                    $stmt->bindValue(':pnode_ip', $pnode_ip, PDO::PARAM_STR);
                    $stmt->execute();

                    echo "<div style='background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; margin: 10px 0;'>✅ DEVICE INSERTED - REDIRECTING</div>";

                    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_success', "Device: $pnode_name, IP: $pnode_ip");
                    header("Location: dashboard.php");
                    exit();
                }
            } catch (PDOException $e) {
                $error = "Error adding device: " . $e->getMessage();
                echo "<div style='background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; margin: 10px 0;'>❌ DATABASE ERROR: " . htmlspecialchars($e->getMessage()) . "</div>";
                error_log($error);
                logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', $error);
            }
        }
    }
}

// Handle edit device
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'edit') {
    // Check if required POST variables exist
    if (!isset($_POST['device_id']) || !isset($_POST['pnode_name']) || !isset($_POST['pnode_ip'])) {
        $error = "Missing required form data.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', 'Missing form data');
    } else {
        $device_id = $_POST['device_id'];
        $pnode_name = trim($_POST['pnode_name']);
        $pnode_ip = trim($_POST['pnode_ip']);

        if (empty($pnode_name) || empty($pnode_ip)) {
            $error = "Please fill in all fields.";
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', 'Empty fields');
        } elseif (strlen($pnode_name) > 100) {
            $error = "Node name must be 100 characters or less.";
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', 'Invalid node name length');
        } elseif (!filter_var($pnode_ip, FILTER_VALIDATE_IP)) {
            $error = "Invalid IP address.";
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', 'Invalid IP address');
        } else {
            try {
                // Check if device belongs to current user
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE id = :device_id AND username = :username");
                $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
                $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
                $stmt->execute();
                if ($stmt->fetchColumn() == 0) {
                    $error = "Device not found or not authorized.";
                    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', 'Unauthorized device access');
                } else {
                    // Check for duplicate name (excluding current device)
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE username = :username AND pnode_name = :pnode_name AND id != :device_id");
                    $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
                    $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
                    $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
                    $stmt->execute();
                    if ($stmt->fetchColumn() > 0) {
                        $error = "Device name already registered.";
                        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', 'Duplicate device name');
                    } else {
                        // Update device
                        $stmt = $pdo->prepare("UPDATE devices SET pnode_name = :pnode_name, pnode_ip = :pnode_ip WHERE id = :device_id AND username = :username");
                        $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
                        $stmt->bindValue(':pnode_ip', $pnode_ip, PDO::PARAM_STR);
                        $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
                        $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
                        $stmt->execute();

                        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_success', "Device ID: $device_id, New Name: $pnode_name, New IP: $pnode_ip");
                        header("Location: dashboard.php");
                        exit();
                    }
                }
            } catch (PDOException $e) {
                $error = "Error editing device: " . $e->getMessage();
                error_log($error);
                logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', $error);
            }
        }
    }
}

// Handle delete device
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'delete') {
    // Check if required POST variable exists
    if (!isset($_POST['device_id'])) {
        $error = "Missing device ID.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_delete_failed', 'Missing device ID');
    } else {
        $device_id = $_POST['device_id'];
        try {
            // Get device details and verify ownership
            $stmt = $pdo->prepare("SELECT pnode_name, pnode_ip FROM devices WHERE id = :device_id AND username = :username");
            $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
            $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
            $stmt->execute();
            $device = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($device) {
                // Delete device (cascade will handle device_status_log)
                $stmt = $pdo->prepare("DELETE FROM devices WHERE id = :device_id AND username = :username");
                $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
                $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
                $stmt->execute();

                logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_delete_success', "Device: {$device['pnode_name']}, IP: {$device['pnode_ip']}");
                header("Location: dashboard.php");
                exit();
            } else {
                $error = "Device not found or not authorized.";
                logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_delete_failed', 'Device not found or unauthorized');
            }
        } catch (PDOException $e) {
            $error = "Error deleting device: " . $e->getMessage();
            error_log($error);
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_delete_failed', $error);
        }
    }
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
    $summaries = [];

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

        // Add the stats section
        $device['pnode_stats'] = null;
        if ($cached_status['status'] === 'Online' && $cached_status['cpu_load_avg'] !== null) {
            $device['pnode_stats'] = [
                'cpu_percent' => $cached_status['cpu_load_avg'],
                'memory_percent' => $cached_status['memory_percent'],
                'total_bytes_transferred' => $cached_status['stats_total_bytes'] ?? 0,
                'total_pages' => $cached_status['stats_total_pages'] ?? 0
            ];
        }

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

        // Parse health data from cached data
        $summaries[$device_id] = parseCachedDeviceHealth($cached_status);

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
                    <li><button class="menu-button active" onclick="window.location.href='dashboard.php'">Dashboard</button></li>
                    <li><button class="menu-button" onclick="window.location.href='device_logs.php'">Device Logs</button></li>
                    <?php if ($_SESSION['admin']): ?>
                        <li class="admin-section">
                            <strong>Admin</strong>
                            <ul>
                                <li><button class="menu-button admin-button" onclick="window.location.href='admin_users.php'">Users</button></li>
                                <li><button class="menu-button admin-button" onclick="window.location.href='devices.php'">Manage Devices</button></li>
                            </ul>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
            <!-- Right Panel -->
            <div class="info-panel">
                <h2>Welcome, <?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name']); ?>!</h2>
                <p class="last-login-text"><span class="last-login-label">Last Login:</span> <?php echo $last_login_display; ?></p>

                <!-- User Details Section -->
                <div style="margin-bottom: 30px;">
                    <h3>Your Details:</h3>
                    <div class="user-details-grid">
                        <div>
                            <div class="user-details-item">
                                <span class="user-details-label">Username:</span>
                                <span class="user-details-value"><?php echo htmlspecialchars($user['username']); ?></span>
                            </div>
                            <div class="user-details-item">
                                <span class="user-details-label">Email:</span>
                                <span class="user-details-value"><?php echo htmlspecialchars($user['email']); ?></span>
                            </div>
                        </div>
                        <div>
                            <div class="user-details-item">
                                <span class="user-details-label">Country:</span>
                                <span class="user-details-value"><?php echo htmlspecialchars($user['country']); ?></span>
                            </div>
                            <div class="user-details-item">
                                <span class="user-details-label">Account Type:</span>
                                <span class="user-details-value"><?php echo $user['admin'] ? 'Administrator' : 'Standard User'; ?></span>
                            </div>
                        </div>
                    </div>
                </div>

                <?php if (isset($error)): ?>
                    <p class="error"><?php echo htmlspecialchars($error); ?></p>
                <?php endif; ?>

                <!-- Device Summary Cards -->
                <?php if (!empty($devices)): ?>
                    <?php
                    $total_devices = count($devices);
                    $online_devices = count(array_filter($devices, function($d) { return $d['status'] === 'Online'; }));
                    $offline_devices = count(array_filter($devices, function($d) { return $d['status'] === 'Offline'; }));
                    $healthy_devices = count(array_filter($devices, function($d) { return $d['overall_status'] === 'Healthy'; }));
                    $issues_devices = count(array_filter($devices, function($d) { return $d['overall_status'] === 'Online (Issues)'; }));
                    ?>
                    <div class="dashboard-summary">
                        <div class="summary-card">
                            <h4>Total Devices</h4>
                            <div class="summary-number summary-total"><?php echo $total_devices; ?></div>
                        </div>
                        <div class="summary-card">
                            <h4>Online</h4>
                            <div class="summary-number summary-online"><?php echo $online_devices; ?></div>
                        </div>
                        <div class="summary-card">
                            <h4>Healthy</h4>
                            <div class="summary-number summary-online"><?php echo $healthy_devices; ?></div>
                        </div>
                        <div class="summary-card">
                            <h4>With Issues</h4>
                            <div class="summary-number summary-issues"><?php echo $issues_devices; ?></div>
                        </div>
                        <div class="summary-card">
                            <h4>Offline</h4>
                            <div class="summary-number summary-offline"><?php echo $offline_devices; ?></div>
                        </div>
                    </div>
                <?php endif; ?>

                <div class="devices-header">
                    <h3 class="devices-title">Your Devices</h3>
                    <button type="button" class="add-device-btn" onclick="openAddModal()" title="Add New Device">+</button>
                </div>
                <?php if (empty($devices)): ?>
                    <p>No devices registered.</p>
                <?php else: ?>
                    <table class="device-table">
                        <thead>
                            <tr>
                                <th class="sortable-header" data-sort="name">
                                    Node Name
                                    <span class="sort-indicator"></span>
                                </th>
                                <th class="sortable-header" data-sort="ip">
                                    IP Address
                                    <span class="sort-indicator"></span>
                                </th>
                                <th>Registration Date</th>
                                <th class="sortable-header" data-sort="connectivity">
                                    Connectivity
                                    <span class="sort-indicator"></span>
                                </th>
                                <th class="sortable-header" data-sort="health">
                                    Health Status
                                    <span class="sort-indicator"></span>
                                </th>
                                <th>Versions</th>
                                <th>pNode Stats</th>
                                <th>Last Checked</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($devices as $device): ?>
                                <tr>
                                    <td><a href="device_details.php?device_id=<?php echo $device['id']; ?>"><?php echo htmlspecialchars($device['pnode_name']); ?></a></td>
                                    <td><?php echo htmlspecialchars($device['pnode_ip']); ?></td>
                                    <td><?php echo htmlspecialchars($device['registration_date']); ?></td>
                                    <td id="status-<?php echo $device['id']; ?>">
                                        <span class="status-btn status-<?php echo strtolower(str_replace(' ', '-', $device['status'])); ?>">
                                            <?php echo htmlspecialchars($device['status']); ?>
                                        </span>
                                        <?php if ($device['consecutive_failures'] > 0): ?>
                                            <div class="device-status-details" style="color: #dc3545;">Failures: <?php echo $device['consecutive_failures']; ?></div>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($device['status'] === 'Not Initialized'): ?>
                                            <span class="status-btn status-value status-not-initialized">Not Initialized</span>
                                        <?php else: ?>
                                            <div class="status-info">
                                                <div><strong>Health:</strong>
                                                    <span class="status-btn status-value status-<?php echo $summaries[$device['id']]['health_status'] == 'pass' ? 'online' : 'offline'; ?>" >
                                                        <?php echo ucfirst($summaries[$device['id']]['health_status'] ?? 'unknown'); ?>
                                                    </span>
                                                </div>
                                                <div><strong>Atlas:</strong>
                                                    <span class="status-btn status-value status-<?php echo $summaries[$device['id']]['atlas_registered'] ? 'online' : 'offline'; ?>" >
                                                        <?php echo $summaries[$device['id']]['atlas_registered'] ? 'Yes' : 'No'; ?>
                                                    </span>
                                                </div>
                                                <div><strong>Pod:</strong>
                                                    <span class="status-btn status-value status-<?php echo $summaries[$device['id']]['pod_status'] == 'active' ? 'online' : 'offline'; ?>" >
                                                        <?php echo ucfirst($summaries[$device['id']]['pod_status'] ?? 'unknown'); ?>
                                                    </span>
                                                </div>
                                                <div><strong>XandMiner:</strong>
                                                    <span class="status-btn status-value status-<?php echo $summaries[$device['id']]['xandminer_status'] == 'active' ? 'online' : 'offline'; ?>" >
                                                        <?php echo ucfirst($summaries[$device['id']]['xandminer_status'] ?? 'unknown'); ?>
                                                    </span>
                                                </div>
                                                <div><strong>XandMinerD:</strong>
                                                    <span class="status-btn status-value status-<?php echo $summaries[$device['id']]['xandminerd_status'] == 'active' ? 'online' : 'offline'; ?>" >
                                                        <?php echo ucfirst($summaries[$device['id']]['xandminerd_status'] ?? 'unknown'); ?>
                                                    </span>
                                                </div>
                                            </div>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($device['status'] === 'Not Initialized'): ?>
                                            <span class="status-btn status-value status-not-initialized">Not Initialized</span>
                                        <?php else: ?>
                                            <div class="status-info">
                                                <div><strong>Controller:</strong>
                                                    <span class="status-value version-value">
                                                        <?php echo htmlspecialchars($summaries[$device['id']]['chillxand_version'] ?? 'N/A'); ?>
                                                    </span>
                                                </div>
                                                <div><strong>Pod:</strong>
                                                    <span class="status-value version-value">
                                                        <?php echo htmlspecialchars($summaries[$device['id']]['pod_version'] ?? 'N/A'); ?>
                                                    </span>
                                                </div>
                                                <div><strong>XandMiner:</strong>
                                                    <span class="status-value version-value">
                                                        <?php echo htmlspecialchars($summaries[$device['id']]['xandminer_version'] ?? 'N/A'); ?>
                                                    </span>
                                                </div>
                                                <div><strong>XandMinerD:</strong>
                                                    <span class="status-value version-value">
                                                        <?php echo htmlspecialchars($summaries[$device['id']]['xandminerd_version'] ?? 'N/A'); ?>
                                                    </span>
                                                </div>
                                            </div>
                                        <?php endif; ?>
                                    </td>
                                    <td class="stats-column" id="stats-<?php echo $device['id']; ?>">
                                        <?php if ($device['status'] !== 'Online'): ?>
                                            <span class="stats-unavailable">Stats unavailable</span>
                                        <?php elseif ($device['pnode_stats'] === null): ?>
                                            <span class="stats-no-data">No stats data</span>
                                        <?php else: ?>
                                            <?php $stats = $device['pnode_stats']; ?>
                                            <div class="stats-info">
                                                <div><strong>CPU:</strong>
                                                    <span class="stat-value stat-cpu" data-value="<?php echo $stats['cpu_percent']; ?>">
                                                        <?php echo number_format($stats['cpu_percent'], 1); ?>%
                                                    </span>
                                                </div>

                                                <div><strong>RAM:</strong>
                                                    <span class="stat-value stat-memory" data-value="<?php echo $stats['memory_percent']; ?>">
                                                        <?php echo number_format($stats['memory_percent'], 1); ?>%
                                                    </span>
                                                </div>

                                                <div><strong>Total Bytes:</strong>
                                                    <span class="stat-value">
                                                        <?php echo formatBytesForDisplay($stats['total_bytes_transferred']); ?>
                                                    </span>
                                                </div>

                                                <div><strong>Pages Used:</strong>
                                                    <span class="stat-value">
                                                        <?php echo number_format($stats['total_pages']); ?>
                                                    </span>
                                                </div>
                                            </div>
                                        <?php endif; ?>
                                    </td>
                                    <td class="last-check-col" id="lastcheck-<?php echo $device['id']; ?>">
                                        <?php if ($device['last_check']): ?>
                                            <div class="<?php echo $device['status_stale'] ? 'status-stale' : 'status-fresh'; ?>">
                                                <?php echo $device['status_age'] ? round($device['status_age']) . ' min ago' : 'Just now'; ?>
                                            </div>
                                            <div class="last-check-date">
                                                <?php echo date('M j, H:i', strtotime($device['last_check'])); ?>
                                            </div>
                                            <?php if ($device['response_time']): ?>
                                                <div class="device-status-details">Response: <?php echo round($device['response_time'] * 1000, 1); ?>ms</div>
                                            <?php endif; ?>
                                        <?php else: ?>
                                            <div class="never-checked">Never checked</div>
                                        <?php endif; ?>
                                    </td>
                                    <td class="actions-column">
                                        <div class="dashboard-actions">
                                            <button type="button" class="action-button edit"
                                                    onclick="openEditModal(<?php echo $device['id']; ?>, '<?php echo htmlspecialchars($device['pnode_name'], ENT_QUOTES); ?>', '<?php echo htmlspecialchars($device['pnode_ip']); ?>')">
                                                Edit
                                            </button>
                                            <button type="button" class="action-button delete"
                                                    onclick="openDeleteModal(<?php echo $device['id']; ?>, '<?php echo htmlspecialchars($device['pnode_name'], ENT_QUOTES); ?>')">
                                                Delete
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>

                <div style="margin-top: 20px; padding: 10px; background-color: #e9ecef; border-radius: 4px;">
                    <h4>Dashboard Information</h4>
                    <p><small>This dashboard provides a read-only view of your devices and their current status.
                    Device health status is automatically updated every 30 seconds per device. Click on any device
                    name to view detailed logs and status history.</small></p>
                </div>
            </div>
        </div>
    </div>

 <script>
        class DeviceStatusUpdater {
            constructor() {
                this.devices = [];
                this.updateInterval = 60000; // 60 seconds per device
                this.deviceStatuses = new Map(); // Track current status of each device
                this.init();
            }

            init() {
                // Collect all device IDs from the table and their initial statuses
                const deviceRows = document.querySelectorAll('.device-table tbody tr');

                deviceRows.forEach((row, index) => {
                    const deviceLink = row.querySelector('td:first-child a');
                    if (deviceLink) {
                        const url = new URL(deviceLink.href);
                        const deviceId = url.searchParams.get('device_id');
                        if (deviceId) {
                            // Get initial status from the row
                            const initialStatus = this.getRowStatus(row);
                            this.deviceStatuses.set(deviceId, initialStatus);

                            this.devices.push({
                                id: deviceId,
                                row: row,
                                lastUpdate: 0
                            });
                        }
                    }
                });

                if (this.devices.length > 0) {
                    // Calculate dynamic stagger delay: spread updates evenly across the 30-second window
                    this.staggerDelay = this.updateInterval / this.devices.length;

                    // Start staggered updates
                    this.startStaggeredUpdates();
                }
            }

            getRowStatus(row) {
                // Extract current status from a table row
                const connectivityCell = row.cells[3];
                const statusBtn = connectivityCell.querySelector('.status-btn');
                const status = statusBtn ? statusBtn.textContent.trim() : 'Unknown';

                // Determine overall status based on current row content
                const healthCell = row.cells[4];
                let overallStatus = 'Unknown';

                if (status === 'Online') {
                    // Check if health shows "Pass" for healthy status
                    const healthText = healthCell.textContent;
                    if (healthText.includes('Pass')) {
                        overallStatus = 'Healthy';
                    } else if (healthText.includes('Fail')) {
                        overallStatus = 'Online (Issues)';
                    } else {
                        overallStatus = 'Online';
                    }
                } else if (status === 'Offline') {
                    overallStatus = 'Offline';
                } else {
                    overallStatus = status;
                }

                return {
                    status: status,
                    overallStatus: overallStatus
                };
            }

            startStaggeredUpdates() {
                this.devices.forEach((device, index) => {
                    const delay = index * this.staggerDelay;

                    // Stagger initial updates
                    setTimeout(() => {
                        this.updateDevice(device);

                        // Set up recurring updates for this device
                        setInterval(() => this.updateDevice(device), this.updateInterval);
                    }, delay);
                });
            }

            async updateDevice(device) {
                try {
                    const response = await fetch(`ajax_device_status.php?device_id=${device.id}`);
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}`);
                    }

                    const data = await response.json();

                    if (data.success) {
                        // Store old status for comparison
                        const oldStatus = this.deviceStatuses.get(device.id);

                        // Update the row
                        this.updateDeviceRow(device, data);

                        // Store new status
                        const newStatus = {
                            status: data.status,
                            overallStatus: data.overall_status
                        };
                        this.deviceStatuses.set(device.id, newStatus);

                        // Update summary cards if status changed or on first update
                        if (!oldStatus ||
                            oldStatus.status !== newStatus.status ||
                            oldStatus.overallStatus !== newStatus.overallStatus) {
                            this.updateSummaryCards();
                        }

                        device.lastUpdate = Date.now();
                    } else {
                        console.error(`Error updating device ${device.id}:`, data.error);
                    }
                } catch (error) {
                    console.error(`Failed to update device ${device.id}:`, error);
                }
            }

            updateSummaryCards() {
                const statuses = Array.from(this.deviceStatuses.values());

                // Calculate totals
                const totalDevices = statuses.length;
                const onlineDevices = statuses.filter(s => s.status === 'Online').length;
                const offlineDevices = statuses.filter(s => s.status === 'Offline').length;
                const healthyDevices = statuses.filter(s => s.overallStatus === 'Healthy').length;
                const issuesDevices = statuses.filter(s => s.overallStatus === 'Online (Issues)').length;

                // Update the summary cards
                const summaryCards = document.querySelectorAll('.summary-card');
                if (summaryCards.length >= 5) {
                    // Total Devices
                    const totalCard = summaryCards[0].querySelector('.summary-number');
                    if (totalCard) totalCard.textContent = totalDevices;

                    // Online
                    const onlineCard = summaryCards[1].querySelector('.summary-number');
                    if (onlineCard) onlineCard.textContent = onlineDevices;

                    // Healthy
                    const healthyCard = summaryCards[2].querySelector('.summary-number');
                    if (healthyCard) healthyCard.textContent = healthyDevices;

                    // With Issues
                    const issuesCard = summaryCards[3].querySelector('.summary-number');
                    if (issuesCard) issuesCard.textContent = issuesDevices;

                    // Offline
                    const offlineCard = summaryCards[4].querySelector('.summary-number');
                    if (offlineCard) offlineCard.textContent = offlineDevices;
                }
            }

            updateDeviceRow(device, data) {
                const row = device.row;

               // Add visual highlight to the entire row
                row.style.backgroundColor = '#fffbf0';
                row.style.transition = 'background-color 0.3s ease';

                // Update connectivity status (4th column)
                const connectivityCell = row.cells[3];
                this.updateConnectivityCell(connectivityCell, data);

                // Update health status (5th column)
                const healthCell = row.cells[4];
                this.updateHealthCell(healthCell, data);

                // Update versions (6th column)
                const versionsCell = row.cells[5];
                this.updateVersionsCell(versionsCell, data);

                // Update pNode stats (7th column) - NEW
                const statsCell = row.cells[6];
                this.updateStatsCell(statsCell, data);

                // Update last checked (8th column)
                const lastCheckedCell = row.cells[7];
                this.updateLastCheckedCell(lastCheckedCell, data);

                // Remove highlight after 2 seconds
                setTimeout(() => {
                    row.style.backgroundColor = '';
                }, 2000);
            }

            updateStatsCell(cell, data) {
                if (data.status !== 'Online') {
                    cell.innerHTML = '<span class="stats-unavailable">Stats unavailable</span>';
                    return;
                }

                // Check if we have stats data in the cached status
                const stats = data.pnode_stats;

                if (!stats || stats.cpu_percent === null) {
                    cell.innerHTML = '<span class="stats-no-data">No stats data</span>';
                    return;
                }

                // Format bytes using the same function as PHP
                const formatBytes = (bytes) => {
                    if (!bytes || bytes < 0) return '0 B';

                    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
                    let size = Math.max(bytes, 0);
                    const pow = Math.floor(Math.log(size) / Math.log(1024));
                    const finalPow = Math.min(pow, units.length - 1);

                    size /= Math.pow(1024, finalPow);
                    return Math.round(size * 10) / 10 + ' ' + units[finalPow];
                };

                // Build the stats HTML with the same structure as PHP
                cell.innerHTML = `
                    <div class="stats-info">
                        <div><strong>CPU:</strong>
                            <span class="stat-value stat-cpu" data-value="${stats.cpu_percent}">
                                ${Number(stats.cpu_percent).toFixed(1)}%
                            </span>
                        </div>

                        <div><strong>RAM:</strong>
                            <span class="stat-value stat-memory" data-value="${stats.memory_percent}">
                                ${Number(stats.memory_percent).toFixed(1)}%
                            </span>
                        </div>

                        <div><strong>Total Bytes:</strong>
                            <span class="stat-value">
                                ${formatBytes(stats.total_bytes_transferred)}
                            </span>
                        </div>

                        <div><strong>Pages Used:</strong>
                            <span class="stat-value">
                                ${Number(stats.total_pages || 0).toLocaleString()}
                            </span>
                        </div>
                    </div>
                `;
            }

            updateConnectivityCell(cell, data) {
                const statusClass = `status-${data.status.toLowerCase().replace(' ', '-')}`;

                cell.innerHTML = `
                    <span class="status-btn ${statusClass}">
                        ${data.status}
                    </span>
                    ${data.consecutive_failures > 0 ? `<div class="device-status-details" style="color: #dc3545;">Failures: ${data.consecutive_failures}</div>` : ''}
                `;
            }

            updateHealthCell(cell, data) {
                if (data.status === 'Not Initialized') {
                    cell.innerHTML = '<span class="status-btn status-value status-not-initialized">Not Initialized</span>';
                    return;
                }

                const summary = data.summary;
                cell.innerHTML = `
                    <div class="status-info">
                        <div><strong>Health:</strong>
                            <span class="status-btn status-value status-${summary.health_status == 'pass' ? 'online' : 'offline'}">
                                ${summary.health_status ? summary.health_status.charAt(0).toUpperCase() + summary.health_status.slice(1) : 'Unknown'}
                            </span>
                        </div>
                        <div><strong>Atlas:</strong>
                            <span class="status-btn status-value status-${summary.atlas_registered ? 'online' : 'offline'}">
                                ${summary.atlas_registered ? 'Yes' : 'No'}
                            </span>
                        </div>
                        <div><strong>Pod:</strong>
                            <span class="status-btn status-value status-${summary.pod_status == 'active' ? 'online' : 'offline'}">
                                ${summary.pod_status ? summary.pod_status.charAt(0).toUpperCase() + summary.pod_status.slice(1) : 'Unknown'}
                            </span>
                        </div>
                        <div><strong>XandMiner:</strong>
                            <span class="status-btn status-value status-${summary.xandminer_status == 'active' ? 'online' : 'offline'}">
                                ${summary.xandminer_status ? summary.xandminer_status.charAt(0).toUpperCase() + summary.xandminer_status.slice(1) : 'Unknown'}
                            </span>
                        </div>
                        <div><strong>XandMinerD:</strong>
                            <span class="status-btn status-value status-${summary.xandminerd_status == 'active' ? 'online' : 'offline'}">
                                ${summary.xandminerd_status ? summary.xandminerd_status.charAt(0).toUpperCase() + summary.xandminerd_status.slice(1) : 'Unknown'}
                            </span>
                        </div>
                    </div>
                `;
            }

            updateVersionsCell(cell, data) {
                if (data.status === 'Not Initialized') {
                    cell.innerHTML = '<span class="status-btn status-value status-not-initialized">Not Initialized</span>';
                    return;
                }

                const summary = data.summary;
                cell.innerHTML = `
                    <div class="status-info">
                        <div><strong>Controller:</strong>
                        <span class="status-value version-value">
                                ${summary.chillxand_version || 'N/A'}
                            </span>
                        </div>
                        <div><strong>Pod:</strong>
                        <span class="status-value version-value">
                                ${summary.pod_version || 'N/A'}
                            </span>
                        </div>
                        <div><strong>XandMiner:</strong>
                        <span class="status-value version-value">
                                ${summary.xandminer_version || 'N/A'}
                            </span>
                        </div>
                        <div><strong>XandMinerD:</strong>
                        <span class="status-value version-value">
                                ${summary.xandminerd_version || 'N/A'}
                            </span>
                        </div>
                    </div>
                `;
            }

            updateLastCheckedCell(cell, data) {
                if (data.last_check) {
                    const ageText = data.status_age ? Math.round(data.status_age) + ' min ago' : 'Just now';
                    const staleClass = data.status_stale ? 'status-stale' : 'status-fresh';
                    const checkDate = new Date(data.last_check);
                    const formattedDate = checkDate.toLocaleDateString('en-US', {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                        hour12: false
                    });

                    cell.innerHTML = `
                        <div class="${staleClass}">
                            ${ageText}
                        </div>
                        <div class="last-check-date">
                            ${formattedDate}
                        </div>
                        ${data.response_time ? `<div class="device-status-details">Response: ${Math.round(data.response_time * 1000)}ms</div>` : ''}
                    `;
                } else {
                    cell.innerHTML = '<div class="never-checked">Never checked</div>';
                }
            }
        }

        // Combined DOMContentLoaded - only ONE event listener
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize device status updater
            if (document.querySelector('.device-table tbody tr')) {
                new DeviceStatusUpdater();
            }

            // Initialize table sorting
            const table = document.querySelector('.device-table');
            if (table) {
                initializeTableSorting(table);
            }
        });

        function initializeTableSorting(table) {
            const headers = table.querySelectorAll('.sortable-header');
            let currentSort = { column: null, direction: 'asc' };

            headers.forEach(header => {
                header.addEventListener('click', function() {
                    const sortType = this.getAttribute('data-sort');

                    // Toggle direction if clicking same column
                    if (currentSort.column === sortType) {
                        currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
                    } else {
                        currentSort.direction = 'asc';
                    }
                    currentSort.column = sortType;

                    // Update visual indicators
                    headers.forEach(h => {
                        h.classList.remove('sort-asc', 'sort-desc');
                    });
                    this.classList.add(currentSort.direction === 'asc' ? 'sort-asc' : 'sort-desc');

                    // Sort the table
                    sortTable(table, sortType, currentSort.direction);
                });
            });
        }

        function sortTable(table, sortType, direction) {
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));

            rows.sort((a, b) => {
                let aValue, bValue;

                switch(sortType) {
                    case 'name':
                        aValue = a.cells[0].textContent.trim().toLowerCase();
                        bValue = b.cells[0].textContent.trim().toLowerCase();
                        break;

                    case 'ip':
                        aValue = a.cells[1].textContent.trim();
                        bValue = b.cells[1].textContent.trim();
                        // Sort IPs numerically
                        return direction === 'asc' ?
                            compareIPs(aValue, bValue) :
                            compareIPs(bValue, aValue);

                    case 'connectivity':
                        aValue = a.cells[3].querySelector('.status-btn').textContent.trim();
                        bValue = b.cells[3].querySelector('.status-btn').textContent.trim();
                        // Custom order: Online, Offline, Error, etc.
                        const connectivityOrder = { 'Online': 1, 'Offline': 2, 'Error': 3, 'Not Initialized': 4 };
                        const aOrder = connectivityOrder[aValue] || 999;
                        const bOrder = connectivityOrder[bValue] || 999;
                        return direction === 'asc' ? aOrder - bOrder : bOrder - aOrder;

                    case 'health':
                        // Get the overall health status from the health column
                        const aHealthElement = a.cells[4].querySelector('.status-btn');
                        const bHealthElement = b.cells[4].querySelector('.status-btn');
                        aValue = aHealthElement ? aHealthElement.textContent.trim() : 'Unknown';
                        bValue = bHealthElement ? bHealthElement.textContent.trim() : 'Unknown';
                        // Custom order: pass/Healthy first, then fail/Issues, then unknown
                        const healthOrder = { 'Pass': 1, 'Healthy': 1, 'Fail': 2, 'Issues': 2, 'Not Initialized': 3, 'Unknown': 4 };
                        const aHealthOrder = healthOrder[aValue] || 999;
                        const bHealthOrder = healthOrder[bValue] || 999;
                        return direction === 'asc' ? aHealthOrder - bHealthOrder : bHealthOrder - aHealthOrder;

                    default:
                        aValue = a.cells[0].textContent.trim().toLowerCase();
                        bValue = b.cells[0].textContent.trim().toLowerCase();
                }

                if (aValue < bValue) return direction === 'asc' ? -1 : 1;
                if (aValue > bValue) return direction === 'asc' ? 1 : -1;
                return 0;
            });

            // Re-append sorted rows
            rows.forEach(row => tbody.appendChild(row));
        }

        function compareIPs(ip1, ip2) {
            const parts1 = ip1.split('.').map(Number);
            const parts2 = ip2.split('.').map(Number);

            for (let i = 0; i < 4; i++) {
                if (parts1[i] !== parts2[i]) {
                    return parts1[i] - parts2[i];
                }
            }
            return 0;
        }

        // Edit Device Functions
        function openEditModal(deviceId, currentName, currentIp) {
            document.getElementById('edit-device-id').value = deviceId;
            document.getElementById('edit-pnode-name').value = currentName;
            document.getElementById('edit-pnode-ip').value = currentIp;

            // Clear any previous errors
            clearEditModalErrors();

            // Hide loading overlay
            hideModalLoading('editModal', 'editModalLoading');

            document.getElementById('editModal').style.display = 'block';

            // Focus on first field
            setTimeout(() => {
                document.getElementById('edit-pnode-name').focus();
            }, 100);
        }

        function closeEditModal() {
            document.getElementById('editModal').style.display = 'none';
            clearEditModalErrors();
            hideModalLoading('editModal', 'editModalLoading');
        }

        function validateAndSubmitEdit() {
            // Clear previous errors
            clearEditModalErrors();

            // Get form references
            const form = document.getElementById('editForm');
            const nameField = document.getElementById('edit-pnode-name');
            const ipField = document.getElementById('edit-pnode-ip');

            // Debug: Check if form elements exist
            if (!form || !nameField || !ipField) {
                console.error('Edit form elements not found:', { form, nameField, ipField });
                showEditModalError('Form elements not found. Please refresh the page and try again.');
                return;
            }

            // Get form values
            const nodeName = nameField.value.trim();
            const ipAddress = ipField.value.trim();

            // Debug log
            console.log('Edit form validation:', { nodeName, ipAddress });

            let hasErrors = false;

            // Validate node name
            const nameError = validateNodeName(nodeName);
            if (nameError) {
                showEditModalError(nameError, 'name');
                hasErrors = true;
            }

            // Validate IP address
            const ipError = validateIPAddress(ipAddress);
            if (ipError) {
                showEditModalError(ipError, 'ip');
                hasErrors = true;
            }

            // If no errors, show loading and submit the form
            if (!hasErrors) {
                // Update form values with trimmed versions
                nameField.value = nodeName;
                ipField.value = ipAddress;

                // Debug: Log form data before submission
                const formData = new FormData(form);
                console.log('Edit form data being submitted:');
                for (let [key, value] of formData.entries()) {
                    console.log(key + ': ' + value);
                }

                // Show loading state
                showModalLoading('editModal', 'editModalLoading');

                // Submit the form
                form.submit();
            }
        }

        function clearEditModalErrors() {
            // Hide main error area
            const errorDiv = document.getElementById('editModalError');
            errorDiv.style.display = 'none';
            errorDiv.innerHTML = '';

            // Hide field-specific errors
            const nameError = document.getElementById('edit-name-error');
            const ipError = document.getElementById('edit-ip-error');
            nameError.style.display = 'none';
            ipError.style.display = 'none';
            nameError.innerHTML = '';
            ipError.innerHTML = '';

            // Remove error styling from inputs
            document.getElementById('edit-pnode-name').classList.remove('input-error');
            document.getElementById('edit-pnode-ip').classList.remove('input-error');
        }

        function showModalError(message, fieldId = null) {
            if (fieldId) {
                // Show field-specific error
                const errorDiv = document.getElementById(fieldId + '-error');
                errorDiv.innerHTML = message;
                errorDiv.style.display = 'block';

                // Add error styling to input
                document.getElementById('add-pnode-' + fieldId).classList.add('input-error');
            } else {
                // Show general error
                const errorDiv = document.getElementById('addModalError');
                errorDiv.innerHTML = '<strong>Error:</strong> ' + message;
                errorDiv.style.display = 'block';
            }
        }

        // Delete Device Functions
        function openDeleteModal(deviceId, deviceName) {
            document.getElementById('delete-device-id').value = deviceId;
            document.getElementById('delete-device-name').textContent = deviceName;

            // Hide loading overlay
            hideModalLoading('deleteModal', 'deleteModalLoading');

            document.getElementById('deleteModal').style.display = 'block';
        }

        function closeDeleteModal() {
            document.getElementById('deleteModal').style.display = 'none';
            hideModalLoading('deleteModal', 'deleteModalLoading');
        }

        function confirmDelete() {
            // Show loading state immediately
            showModalLoading('deleteModal', 'deleteModalLoading');

            // Submit the form
            document.getElementById('deleteForm').submit();
        }

        function submitDelete() {
            document.getElementById('deleteForm').submit();
        }

        // UPDATE your existing window.onclick function to include the new modals
        window.onclick = function(event) {
            const addModal = document.getElementById('addModal');
            const editModal = document.getElementById('editModal');
            const deleteModal = document.getElementById('deleteModal');

            if (event.target == addModal) {
                closeAddModal();
            }
            if (event.target == editModal) {
                closeEditModal();
            }
            if (event.target == deleteModal) {
                closeDeleteModal();
            }
        }

        // UPDATE your existing keydown event listener to include the new modals
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeAddModal();
                closeEditModal();
                closeDeleteModal();
            }
        });

        function showEditModalError(message, fieldId = null) {
            if (fieldId) {
                // Show field-specific error
                const errorDiv = document.getElementById('edit-' + fieldId + '-error');
                errorDiv.innerHTML = message;
                errorDiv.style.display = 'block';

                // Add error styling to input
                document.getElementById('edit-pnode-' + fieldId).classList.add('input-error');
            } else {
                // Show general error
                const errorDiv = document.getElementById('editModalError');
                errorDiv.innerHTML = '<strong>Error:</strong> ' + message;
                errorDiv.style.display = 'block';
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            // Add form validation
            const nameInput = document.getElementById('add-pnode-name');
            const ipInput = document.getElementById('add-pnode-ip');

            if (nameInput) {
                nameInput.addEventListener('blur', function() {
                    const nameError = validateNodeName(this.value.trim());
                    const errorDiv = document.getElementById('name-error');

                    if (nameError) {
                        errorDiv.innerHTML = nameError;
                        errorDiv.style.display = 'block';
                        this.classList.add('input-error');
                    } else {
                        errorDiv.style.display = 'none';
                        this.classList.remove('input-error');
                    }
                });

                nameInput.addEventListener('input', function() {
                    if (this.classList.contains('input-error')) {
                        document.getElementById('name-error').style.display = 'none';
                        this.classList.remove('input-error');
                    }
                });
            }

            if (ipInput) {
                ipInput.addEventListener('blur', function() {
                    const ipError = validateIPAddress(this.value.trim());
                    const errorDiv = document.getElementById('ip-error');

                    if (ipError) {
                        errorDiv.innerHTML = ipError;
                        errorDiv.style.display = 'block';
                        this.classList.add('input-error');
                    } else {
                        errorDiv.style.display = 'none';
                        this.classList.remove('input-error');
                    }
                });

                ipInput.addEventListener('input', function() {
                    if (this.classList.contains('input-error')) {
                        document.getElementById('ip-error').style.display = 'none';
                        this.classList.remove('input-error');
                    }
                });
            }

            // Edit form validation
            const editNameInput = document.getElementById('edit-pnode-name');
            const editIpInput = document.getElementById('edit-pnode-ip');

            if (editNameInput) {
                editNameInput.addEventListener('blur', function() {
                    const nameError = validateNodeName(this.value.trim());
                    const errorDiv = document.getElementById('edit-name-error');

                    if (nameError) {
                        errorDiv.innerHTML = nameError;
                        errorDiv.style.display = 'block';
                        this.classList.add('input-error');
                    } else {
                        errorDiv.style.display = 'none';
                        this.classList.remove('input-error');
                    }
                });

                editNameInput.addEventListener('input', function() {
                    if (this.classList.contains('input-error')) {
                        document.getElementById('edit-name-error').style.display = 'none';
                        this.classList.remove('input-error');
                    }
                });
            }

            if (editIpInput) {
                editIpInput.addEventListener('blur', function() {
                    const ipError = validateIPAddress(this.value.trim());
                    const errorDiv = document.getElementById('edit-ip-error');

                    if (ipError) {
                        errorDiv.innerHTML = ipError;
                        errorDiv.style.display = 'block';
                        this.classList.add('input-error');
                    } else {
                        errorDiv.style.display = 'none';
                        this.classList.remove('input-error');
                    }
                });

                editIpInput.addEventListener('input', function() {
                    if (this.classList.contains('input-error')) {
                        document.getElementById('edit-ip-error').style.display = 'none';
                        this.classList.remove('input-error');
                    }
                });
            }
        });

        // Loading state management
        function showModalLoading(modalId, loadingId) {
            document.getElementById(loadingId).style.display = 'flex';

            // Disable all buttons in the modal, but NOT the form inputs
            const modal = document.getElementById(modalId);
            const buttons = modal.querySelectorAll('button');
            const closeBtn = modal.querySelector('.close');

            buttons.forEach(btn => btn.disabled = true);
            if (closeBtn) closeBtn.style.pointerEvents = 'none';

            // Make form inputs readonly instead of disabled (so they still submit)
            const inputs = modal.querySelectorAll('input[type="text"]');
            inputs.forEach(input => {
                input.readOnly = true;
                input.style.backgroundColor = '#f8f9fa';
                input.style.cursor = 'not-allowed';
            });
        }

        function hideModalLoading(modalId, loadingId) {
            document.getElementById(loadingId).style.display = 'none';

            // Re-enable all buttons
            const modal = document.getElementById(modalId);
            const buttons = modal.querySelectorAll('button');
            const closeBtn = modal.querySelector('.close');

            buttons.forEach(btn => btn.disabled = false);
            if (closeBtn) closeBtn.style.pointerEvents = 'auto';

            // Remove readonly from inputs
            const inputs = modal.querySelectorAll('input[type="text"]');
            inputs.forEach(input => {
                input.readOnly = false;
                input.style.backgroundColor = '';
                input.style.cursor = '';
            });
        }

        // Add Modal
        function openAddModal() {
            // Clear form fields
            document.getElementById('add-pnode-name').value = '';
            document.getElementById('add-pnode-ip').value = '';

            // Clear any previous errors
            clearModalErrors();

            // Hide loading overlay
            hideModalLoading('addModal', 'addModalLoading');

            // Show modal
            document.getElementById('addModal').style.display = 'block';

            // Focus on first field
            setTimeout(() => {
                document.getElementById('add-pnode-name').focus();
            }, 100);
        }

        function closeAddModal() {
            document.getElementById('addModal').style.display = 'none';
            clearModalErrors();
            hideModalLoading('addModal', 'addModalLoading');
        }

        function clearModalErrors() {
            // Hide main error area
            const errorDiv = document.getElementById('addModalError');
            errorDiv.style.display = 'none';
            errorDiv.innerHTML = '';

            // Hide field-specific errors
            const nameError = document.getElementById('name-error');
            const ipError = document.getElementById('ip-error');
            nameError.style.display = 'none';
            ipError.style.display = 'none';
            nameError.innerHTML = '';
            ipError.innerHTML = '';

            // Remove error styling from inputs
            document.getElementById('add-pnode-name').classList.remove('input-error');
            document.getElementById('add-pnode-ip').classList.remove('input-error');
        }

        function showModalError(message, fieldId = null) {
            if (fieldId) {
                // Show field-specific error
                const errorDiv = document.getElementById(fieldId + '-error');
                errorDiv.innerHTML = message;
                errorDiv.style.display = 'block';

                // Add error styling to input
                document.getElementById('add-pnode-' + fieldId).classList.add('input-error');
            } else {
                // Show general error
                const errorDiv = document.getElementById('addModalError');
                errorDiv.innerHTML = '<strong>Error:</strong> ' + message;
                errorDiv.style.display = 'block';
            }
        }

        function validateNodeName(name) {
            if (!name || name.trim() === '') {
                return 'Node name is required.';
            }

            if (name.length > 100) {
                return 'Node name must be 100 characters or less.';
            }

            // Check for valid characters (letters, numbers, spaces, hyphens, underscores)
            const validPattern = /^[a-zA-Z0-9\s\-_]+$/;
            if (!validPattern.test(name)) {
                return 'Node name can only contain letters, numbers, spaces, hyphens, and underscores.';
            }

            return null; // Valid
        }

        function validateIPAddress(ip) {
            if (!ip || ip.trim() === '') {
                return 'IP address is required.';
            }

            // Basic IP address pattern
            const ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
            const match = ip.match(ipPattern);

            if (!match) {
                return 'Please enter a valid IP address (e.g., 192.168.1.100).';
            }

            // Check each octet is between 0-255
            for (let i = 1; i <= 4; i++) {
                const octet = parseInt(match[i]);
                if (octet < 0 || octet > 255) {
                    return 'IP address octets must be between 0 and 255.';
                }
            }

            return null; // Valid
        }

        function validateAndSubmit() {
            // Clear previous errors
            clearModalErrors();

            // Get form values
            const nodeName = document.getElementById('add-pnode-name').value.trim();
            const ipAddress = document.getElementById('add-pnode-ip').value.trim();

            let hasErrors = false;

            // Validate node name
            const nameError = validateNodeName(nodeName);
            if (nameError) {
                showModalError(nameError, 'name');
                hasErrors = true;
            }

            // Validate IP address
            const ipError = validateIPAddress(ipAddress);
            if (ipError) {
                showModalError(ipError, 'ip');
                hasErrors = true;
            }

            // If no errors, submit the form
            if (!hasErrors) {
                // Update form values with trimmed versions
                document.getElementById('add-pnode-name').value = nodeName;
                document.getElementById('add-pnode-ip').value = ipAddress;

                // Show loading state AFTER setting the values but BEFORE submit
                showModalLoading('addModal', 'addModalLoading');

                // Submit the form immediately
                document.getElementById('addForm').submit();
            }
        }

        // Prevent multiple modal opens during loading
        function preventModalCloseDuringLoading(event) {
            const loadingOverlays = document.querySelectorAll('.modal-loading-overlay');
            for (let overlay of loadingOverlays) {
                if (overlay.style.display === 'flex') {
                    event.preventDefault();
                    event.stopPropagation();
                    return false;
                }
            }
            return true;
        }

        // Add real-time validation on input
        document.addEventListener('DOMContentLoaded', function() {
            const nameInput = document.getElementById('add-pnode-name');
            const ipInput = document.getElementById('add-pnode-ip');

            if (nameInput) {
                nameInput.addEventListener('blur', function() {
                    const nameError = validateNodeName(this.value.trim());
                    const errorDiv = document.getElementById('name-error');

                    if (nameError) {
                        errorDiv.innerHTML = nameError;
                        errorDiv.style.display = 'block';
                        this.classList.add('input-error');
                    } else {
                        errorDiv.style.display = 'none';
                        this.classList.remove('input-error');
                    }
                });

                nameInput.addEventListener('input', function() {
                    // Clear error when user starts typing
                    if (this.classList.contains('input-error')) {
                        document.getElementById('name-error').style.display = 'none';
                        this.classList.remove('input-error');
                    }
                });
            }

            if (ipInput) {
                ipInput.addEventListener('blur', function() {
                    const ipError = validateIPAddress(this.value.trim());
                    const errorDiv = document.getElementById('ip-error');

                    if (ipError) {
                        errorDiv.innerHTML = ipError;
                        errorDiv.style.display = 'block';
                        this.classList.add('input-error');
                    } else {
                        errorDiv.style.display = 'none';
                        this.classList.remove('input-error');
                    }
                });

                ipInput.addEventListener('input', function() {
                    // Clear error when user starts typing
                    if (this.classList.contains('input-error')) {
                        document.getElementById('ip-error').style.display = 'none';
                        this.classList.remove('input-error');
                    }
                });
            }
        });

        // Updated modal close handlers
        window.onclick = function(event) {
            if (!preventModalCloseDuringLoading(event)) return;

            const addModal = document.getElementById('addModal');
            const editModal = document.getElementById('editModal');
            const deleteModal = document.getElementById('deleteModal');

            if (event.target == addModal) {
                closeAddModal();
            }
            if (event.target == editModal) {
                closeEditModal();
            }
            if (event.target == deleteModal) {
                closeDeleteModal();
            }
        }

        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                if (!preventModalCloseDuringLoading(event)) return;

                closeAddModal();
                closeEditModal();
                closeDeleteModal();
            }
        });
    </script>

    <!-- Add Device Modal -->
    <div id="addModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Add New Device</h3>
                <span class="close" onclick="closeAddModal()">&times;</span>
            </div>

            <!-- Error display area -->
            <div id="addModalError" class="modal-error" style="display: none;"></div>

            <form id="addForm" method="POST" action="">
                <input type="hidden" name="action" value="add">
                <div class="modal-form-group">
                    <label for="add-pnode-name">Node Name: <span class="required">*</span></label>
                    <input type="text"
                        id="add-pnode-name"
                        name="pnode_name"
                        required
                        maxlength="100"
                        placeholder="Enter device name">
                    <div class="field-error" id="name-error" style="display: none;"></div>
                </div>
                <div class="modal-form-group">
                    <label for="add-pnode-ip">IP Address: <span class="required">*</span></label>
                    <input type="text"
                        id="add-pnode-ip"
                        name="pnode_ip"
                        required
                        placeholder="e.g., 192.168.1.100">
                    <div class="field-error" id="ip-error" style="display: none;"></div>
                </div>
                <div class="modal-buttons">
                    <button type="button" class="modal-btn modal-btn-secondary" id="add-cancel-btn" onclick="closeAddModal()">Cancel</button>
                    <button type="button" class="modal-btn modal-btn-primary" id="add-submit-btn" onclick="validateAndSubmit()">Add Device</button>
                </div>
            </form>

            <!-- Loading overlay -->
            <div class="modal-loading-overlay" id="addModalLoading">
                <div class="modal-loading-content">
                    <div class="modal-loading-spinner"></div>
                    <div class="modal-loading-text">Adding device...</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit Device Modal -->
    <div id="editModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Edit Device</h3>
                <span class="close" onclick="closeEditModal()">&times;</span>
            </div>

            <!-- Error display area -->
            <div id="editModalError" class="modal-error" style="display: none;"></div>

            <form id="editForm" method="POST" action="">
                <input type="hidden" name="action" value="edit">
                <input type="hidden" id="edit-device-id" name="device_id">
                <div class="modal-form-group">
                    <label for="edit-pnode-name">Node Name: <span class="required">*</span></label>
                    <input type="text"
                        id="edit-pnode-name"
                        name="pnode_name"
                        required
                        maxlength="100">
                    <div class="field-error" id="edit-name-error" style="display: none;"></div>
                </div>
                <div class="modal-form-group">
                    <label for="edit-pnode-ip">IP Address: <span class="required">*</span></label>
                    <input type="text"
                        id="edit-pnode-ip"
                        name="pnode_ip"
                        required>
                    <div class="field-error" id="edit-ip-error" style="display: none;"></div>
                </div>
                <div class="modal-buttons">
                    <button type="button" class="modal-btn modal-btn-secondary" id="edit-cancel-btn" onclick="closeEditModal()">Cancel</button>
                    <button type="button" class="modal-btn modal-btn-primary" id="edit-submit-btn" onclick="validateAndSubmitEdit()">Save Changes</button>
                </div>
            </form>

            <!-- Loading overlay -->
            <div class="modal-loading-overlay" id="editModalLoading">
                <div class="modal-loading-content">
                    <div class="modal-loading-spinner"></div>
                    <div class="modal-loading-text">Saving changes...</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Delete Device Modal -->
    <div id="deleteModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Delete Device</h3>
                <span class="close" onclick="closeDeleteModal()">&times;</span>
            </div>
            <form id="deleteForm" method="POST" action="">
                <input type="hidden" name="action" value="delete">
                <input type="hidden" id="delete-device-id" name="device_id">
                <p><strong>Are you sure you want to delete the device "<span id="delete-device-name"></span>"?</strong></p>
                <p style="color: #dc3545; font-weight: bold;">⚠️ This action cannot be undone!</p>
                <p>This will permanently remove the device and all its associated data from the system.</p>
                <div class="modal-buttons">
                    <button type="button" class="modal-btn modal-btn-secondary" id="delete-cancel-btn" onclick="closeDeleteModal()">Cancel</button>
                    <button type="button" class="modal-btn modal-btn-danger" id="delete-submit-btn" onclick="confirmDelete()">Delete Device</button>
                </div>
            </form>

            <!-- Loading overlay -->
            <div class="modal-loading-overlay" id="deleteModalLoading">
                <div class="modal-loading-content">
                    <div class="modal-loading-spinner"></div>
                    <div class="modal-loading-text">Deleting device...</div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>