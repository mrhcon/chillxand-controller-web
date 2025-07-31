<?php
// devices.php - Complete working device management with update functionality
session_start();

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once 'db_connect.php';
require_once 'functions.php';

// Set reasonable execution limits
set_time_limit(30);
ini_set('max_execution_time', 30);

// CLI mock session for testing
if (PHP_SAPI === 'cli') {
    $_SESSION['user_id'] = 1;
    $_SESSION['username'] = 'test_user';
    $_SESSION['admin'] = 0;
    error_log("CLI mode: Mock session set");
}

// Check if PDO is initialized
if (!isset($pdo) || $pdo === null) {
    $error = "Database connection error. Please contact the administrator.";
    error_log("PDO object is null in devices.php");
    if (PHP_SAPI !== 'cli') {
        echo "<p class='error'>" . htmlspecialchars($error) . "</p>";
        exit();
    } else {
        echo $error . "\n";
        exit(1);
    }
}

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    if (PHP_SAPI !== 'cli') {
        header("Location: login.php");
        exit();
    } else {
        error_log("No user_id in session for CLI execution.");
        echo "Error: No user session available in CLI mode.\n";
        exit(1);
    }
}

// Fetch admin status
try {
    $stmt = $pdo->prepare("SELECT admin FROM users WHERE id = :user_id");
    $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) {
        $error = "User not found for ID: {$_SESSION['user_id']}";
        error_log($error);
        if (PHP_SAPI !== 'cli') {
            header("Location: login.php");
            exit();
        } else {
            echo "$error\n";
            exit(1);
        }
    }
    $_SESSION['admin'] = $user['admin'];
    error_log("Admin status fetched: admin={$_SESSION['admin']}");
} catch (PDOException $e) {
    $error = "Error fetching user details: " . $e->getMessage();
    error_log($error);
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'user_fetch_failed', $error);
}

// Fetch user's devices with latest status (FAST - no blocking operations!)
try {
    $stmt = $pdo->prepare("
        SELECT d.id, d.pnode_name, d.pnode_ip, d.registration_date
        FROM devices d
        WHERE d.username = :username OR :admin = 1
        ORDER BY d.pnode_name ASC
    ");
    $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
    $stmt->bindValue(':admin', $_SESSION['admin'], PDO::PARAM_INT);
    $stmt->execute();
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
    error_log("Fetched " . count($devices) . " devices for user {$_SESSION['username']}");

    // Get latest statuses for all devices at once (super efficient!)
    $device_ids = array_column($devices, 'id');
    $cached_statuses = getLatestDeviceStatuses($pdo, $device_ids);

    // Add cached status and health data to each device
    $updated_devices = [];
    $summaries = [];
    $limit = 3;

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

        // Parse health data from cached data
        $summaries[$device_id] = parseCachedDeviceHealth($cached_status);

        // Fetch initial device status logs (instead of user interactions)
        $sql = "
            SELECT status, check_time, response_time, error_message, health_status,
                   atlas_registered, pod_status, xandminer_status, xandminerd_status,
                   cpu_load_avg, memory_percent, consecutive_failures
            FROM device_status_log
            WHERE device_id = :device_id
            ORDER BY check_time DESC
            LIMIT :limit
        ";
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
        $stmt->bindValue(':limit', (int)$limit, PDO::PARAM_INT);
        $stmt->execute();
        $device['logs'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Count total device status logs
        $sql = "
            SELECT COUNT(*)
            FROM device_status_log
            WHERE device_id = :device_id
        ";
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
        $stmt->execute();
        $device['total_logs'] = $stmt->fetchColumn();

        $updated_devices[] = $device;
    }
    $devices = $updated_devices;

} catch (PDOException $e) {
    $error = "Error fetching devices or logs: " . $e->getMessage();
    error_log("PDOException in device/log fetch: " . $e->getMessage());
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_fetch_failed', $error);
}

// Handle add device
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'add') {
    $pnode_name = trim($_POST['pnode_name']);
    $pnode_ip = trim($_POST['pnode_ip']);

    if (empty($pnode_name) || empty($pnode_ip)) {
        $error = "Please fill in all fields.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', 'Empty fields');
    } elseif (strlen($pnode_name) > 100) {
        $error = "Node name must be 100 characters or less.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', 'Invalid node name length');
    } elseif (!filter_var($pnode_ip, FILTER_VALIDATE_IP)) {
        $error = "Invalid IP address.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', 'Invalid IP address');
    } else {
        try {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE username = :username AND pnode_name = :pnode_name");
            $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
            $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
            $stmt->execute();
            if ($stmt->fetchColumn() > 0) {
                $error = "Device name already registered.";
                logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', 'Duplicate device name');
            } else {
                // Add device (no seeding required)
                $stmt = $pdo->prepare("INSERT INTO devices (username, pnode_name, pnode_ip, registration_date) VALUES (:username, :pnode_name, :pnode_ip, NOW())");
                $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
                $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
                $stmt->bindValue(':pnode_ip', $pnode_ip, PDO::PARAM_STR);
                $stmt->execute();

                // Get the new device ID (no seeding required - system handles gracefully)
                $new_device_id = $pdo->lastInsertId();

                logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_success', "Device: $pnode_name, IP: $pnode_ip");
                if (PHP_SAPI !== 'cli') {
                    header("Location: devices.php");
                    exit();
                } else {
                    echo "Device added successfully: $pnode_name, $pnode_ip\n";
                }
            }
        } catch (PDOException $e) {
            $error = "Error adding device: " . $e->getMessage();
            error_log($error);
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', $error);
        }
    }
}

// Handle edit device
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'edit') {
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
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE id = :device_id AND (username = :username OR :admin = 1)");
            $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
            $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
            $stmt->bindValue(':admin', $_SESSION['admin'], PDO::PARAM_INT);
            $stmt->execute();
            if ($stmt->fetchColumn() == 0) {
                $error = "Device not found or not authorized.";
                logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', 'Unauthorized device access');
            } else {
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE username = :username AND pnode_name = :pnode_name AND id != :device_id");
                $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
                $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
                $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
                $stmt->execute();
                if ($stmt->fetchColumn() > 0) {
                    $error = "Device name already registered.";
                    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', 'Duplicate device name');
                } else {
                    $stmt = $pdo->prepare("UPDATE devices SET pnode_name = :pnode_name, pnode_ip = :pnode_ip WHERE id = :device_id AND (username = :username OR :admin = 1)");
                    $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
                    $stmt->bindValue(':pnode_ip', $pnode_ip, PDO::PARAM_STR);
                    $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
                    $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
                    $stmt->bindValue(':admin', $_SESSION['admin'], PDO::PARAM_INT);
                    $stmt->execute();

                    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_success', "Device ID: $device_id, New Name: $pnode_name, New IP: $pnode_ip");
                    if (PHP_SAPI !== 'cli') {
                        header("Location: devices.php");
                        exit();
                    } else {
                        echo "Device edited successfully: ID=$device_id, $pnode_name, $pnode_ip\n";
                    }
                }
            }
        } catch (PDOException $e) {
            $error = "Error editing device: " . $e->getMessage();
            error_log($error);
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', $error);
        }
    }
}

// Handle delete device
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'delete') {
    $device_id = $_POST['device_id'];
    try {
        $stmt = $pdo->prepare("SELECT pnode_name, pnode_ip FROM devices WHERE id = :device_id AND (username = :username OR :admin = 1)");
        $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
        $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
        $stmt->bindValue(':admin', $_SESSION['admin'], PDO::PARAM_INT);
        $stmt->execute();
        $device = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($device) {
            // Delete device (cascade will handle device_status_log)
            $stmt = $pdo->prepare("DELETE FROM devices WHERE id = :device_id AND (username = :username OR :admin = 1)");
            $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
            $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
            $stmt->bindValue(':admin', $_SESSION['admin'], PDO::PARAM_INT);
            $stmt->execute();
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_delete_success', "Device: {$device['pnode_name']}, IP: {$device['pnode_ip']}");
            if (PHP_SAPI !== 'cli') {
                header("Location: devices.php");
                exit();
            } else {
                echo "Device deleted successfully: {$device['pnode_name']}, {$device['pnode_ip']}\n";
            }
        } else {
            $error = "Device not found or not authorized.";
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_delete_failed', 'Unauthorized device access');
        }
    } catch (PDOException $e) {
        $error = "Error deleting device: " . $e->getMessage();
        error_log($error);
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_delete_failed', $error);
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Devices</title>
    <link rel="icon" type="image/x-icon" href="images/favicon.ico">
    <link rel="icon" type="image/png" sizes="32x32" href="images/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="images/favicon-16x16.png">
    <link rel="stylesheet" href="style.css">
    <style>
        .summary-container { margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; background: #f9f9f9; }
        .action-btn-tiny {
            padding: 5px 8px;
            margin: 2px;
            cursor: pointer;
            display: inline-block;
            vertical-align: top;
            min-width: 50px;
            width: 120x;
            text-align: center;
            font-size: 10px;
            border: 1px solid #ddd;
            border-radius: 3px;
            background-color: #f8f9fa;
            color: #495057;
            box-sizing: border-box;
        }
        .action-btn-tiny:hover {
            background-color: #e9ecef;
            border-color: #adb5bd;
        }

        .action-btn-tiny.action-edit {
            background-color: #17a2b8;
            color: white;
            border-color: #17a2b8;
        }

        .action-btn-tiny.action-edit:hover {
            background-color: #138496;
            border-color: #117a8b;
        }

        .action-btn-tiny.action-delete {
            background-color: #dc3545;
            color: white;
            border-color: #dc3545;
        }

        .action-btn-tiny.action-delete:hover {
            background-color: #c82333;
            border-color: #bd2130;
        }
        .error { color: red; }
        .status-age { font-size: 10px; color: #666; }
        .status-stale { color: #ff6600; }
        .status-fresh { color: #006600; }
        .refresh-btn {
            background-color: #17a2b8;
            color: white;
            border: none;
            padding: 3px 6px;
            font-size: 11px;
            border-radius: 3px;
            cursor: pointer;
            margin-left: 5px;
            width: 18px;
            height: 18px;
            line-height: 1;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
        }
        .refresh-btn:hover {
            background-color: #138496;
            transform: scale(1.1);
        }
        .refresh-btn:disabled {
            background-color: #6c757d;
            cursor: not-allowed;
            transform: none;
        }
        .device-details { font-size: 11px; color: #666; margin-top: 3px; }
        .status-not-initialized { background-color: #6c757d; }
        .status-healthy { background-color: #28a745; }
        .status-online-issues { background-color: #ffc107; color: #212529; }
        .last-check-col { font-size: 11px; color: #666; }
        .never-checked { font-style: italic; color: #999; }
        .status-log-table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 11px; }
        .status-log-table th, .status-log-table td {
            border: 1px solid #ddd;
            padding: 4px;
            text-align: left;
            font-size: 11px;
            vertical-align: top;
        }
        .status-log-table th { background-color: #f8f9fa; font-weight: bold; }
        .log-status-online { color: #28a745; font-weight: bold; }
        .log-status-offline { color: #dc3545; font-weight: bold; }
        .log-status-error { color: #ffc107; font-weight: bold; }
        .log-health-pass { color: #28a745; }
        .log-health-fail { color: #dc3545; }
        .log-atlas-yes { color: #28a745; }
        .log-atlas-no { color: #dc3545; }
        .log-service-active { color: #28a745; }
        .log-service-inactive { color: #dc3545; }
        .log-metrics { font-size: 10px; color: #666; }
        .log-error { color: #dc3545; font-size: 10px; }

        .update-btn-controller, .update-btn-pod {
            padding: 5px 8px;
            margin: 2px;
            cursor: pointer;
            display: inline-block;
            vertical-align: top;
            min-width: 50px;
            width: 120x;
            text-align: center;
            font-size: 10px;
            border: none;
            border-radius: 3px;
            color: white;
            box-sizing: border-box; /* Important for consistent sizing */
        }

        .update-btn-controller {
            background-color: #fd7e14;
        }

        .update-btn-controller:hover {
            background-color: #e66a00;
        }

        .update-btn-controller:disabled {
            background-color: #ccc;
            cursor: not-allowed;
        }

        .update-btn-pod {
            background-color: #6f42c1;
        }

        .update-btn-pod:hover {
            background-color: #59359a;
        }

        .update-btn-pod:disabled {
            background-color: #ccc;
            cursor: not-allowed;
        }

        /* Modal styling */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        .modal-content {
            background-color: #fefefe;
            margin: 15% auto;
            padding: 20px;
            border: 1px solid #888;
            border-radius: 5px;
            width: 400px;
            max-width: 90%;
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .close {
            color: #aaa;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        .close:hover {
            color: black;
        }
        .modal-form-group {
            margin-bottom: 15px;
        }
        .modal-form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        .modal-form-group input {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 3px;
            box-sizing: border-box;
        }
        .modal-buttons {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }
        .modal-btn {
            padding: 8px 16px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        .modal-btn-primary {
            background-color: #007bff;
            color: white;
        }
        .modal-btn-primary:hover {
            background-color: #0056b3;
        }
        .modal-btn-secondary {
            background-color: #6c757d;
            color: white;
        }
        .modal-btn-secondary:hover {
            background-color: #545b62;
        }
        .modal-btn-danger {
            background-color: #dc3545;
            color: white;
        }
        .modal-btn-danger:hover {
            background-color: #c82333;
        }
        .modal-btn-warning {
            background-color: #ffc107;
            color: #212529;
        }
        .modal-btn-warning:hover {
            background-color: #e0a800;
        }
        .action-btn {
            background-color: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .action-btn:hover {
            background-color: #0056b3;
        }
        .version-info {
            font-size: 10px;
            line-height: 1.3;
            color: #666;
        }
        .version-value {
            font-family: 'Courier New', monospace;
            color: #333;
            font-weight: 500;
        }
        .dashboard-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .summary-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            text-align: center;
        }
        .summary-card h4 {
            margin: 0 0 10px 0;
            color: #495057;
        }
        .summary-number {
            font-size: 24px;
            font-weight: bold;
            margin: 5px 0;
        }
        .summary-online { color: #28a745; }
        .summary-offline { color: #dc3545; }
        .summary-total { color: #007bff; }
        .summary-issues { color: #ffc107; }
        .update-status-icon {
                display: inline-block;
                width: 16px;
                height: 16px;
                margin-left: 5px;
                vertical-align: middle;
                font-size: 14px;
                line-height: 1;
                cursor: help;
            }

            .update-status-error {
                color: #dc3545;
            }

            .update-status-warning {
                color: #ffc107;
            }

            .update-status-success {
                color: #28a745;
            }

            .update-status-icon:hover {
                opacity: 0.8;
            }
    </style>
</head>
<body>
    <div class="console-container">
        <div class="top-bar">
            <h1>ChillXand - pNode Management Console</h1>
            <div class="user-info">
                <span>Welcome, <?php echo htmlspecialchars($_SESSION['username'] ?? 'Guest'); ?></span>
                <a href="logout.php" class="logout-btn">Logout</a>
            </div>
        </div>
        <div class="main-content">
            <div class="menu-column">
                <img src="images/logo.png">
                <ul>
                    <li><button class="menu-button" onclick="window.location.href='dashboard.php'">Dashboard</button></li>
                    <li><button class="menu-button active" onclick="window.location.href='devices.php'">Manage Devices</button></li>
                    <li><button class="menu-button" onclick="window.location.href='device_logs.php'">Device Logs</button></li>
                    <?php if ($_SESSION['admin'] ?? false): ?>
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
            <div class="info-panel">
                <h2>Manage Devices</h2>
                <?php if (isset($error)): ?>
                    <p class="error"><?php echo htmlspecialchars($error); ?></p>
                <?php endif; ?>

                <div style="margin-bottom: 20px;">
                    <button type="button" class="action-btn" id="add-device-btn" onclick="openAddModal()">Add New Device</button>
                </div>

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

                <h3>Your Devices</h3>
                <?php if (empty($devices)): ?>
                    <p>No devices registered.</p>
                <?php else: ?>
                    <table class="device-table">
                        <thead>
                            <tr>
                                <th>Node Name</th>
                                <th>IP Address</th>
                                <th>Registration Date</th>
                                <th>Connectivity</th>
                                <th>Health Status</th>
                                <th>Versions</th>
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
                                        <button class="refresh-btn" id="refresh-<?php echo $device['id']; ?>" onclick="refreshDeviceStatus(<?php echo $device['id']; ?>)" title="Refresh status">↻</button>
                                       <div class="status-age <?php echo $device['status_stale'] ? 'status-stale' : 'status-fresh'; ?>">
                                           <?php if ($device['last_check']): ?>
                                               <?php echo $device['status_age'] ? round($device['status_age']) . 'm ago' : 'Just now'; ?>
                                           <?php else: ?>
                                               Never checked
                                           <?php endif; ?>
                                       </div>
                                       <?php if ($device['response_time']): ?>
                                           <div class="device-details">Response: <?php echo round($device['response_time'] * 1000, 1); ?>ms</div>
                                       <?php endif; ?>
                                       <?php if ($device['consecutive_failures'] > 0): ?>
                                           <div class="device-details" style="color: #dc3545;">Failures: <?php echo $device['consecutive_failures']; ?></div>
                                       <?php endif; ?>
                                   </td>
                                   <td>
                                       <?php if ($device['status'] === 'Not Initialized'): ?>
                                           <span class="status-btn status-not-initialized">Not Initialized</span>
                                       <?php else: ?>
                                           <div style="font-size: 10px; line-height: 1.3;">
                                               <div><strong>Health:</strong>
                                                   <span class="status-btn status-<?php echo $summaries[$device['id']]['health_status'] == 'pass' ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
                                                       <?php echo ucfirst($summaries[$device['id']]['health_status'] ?? 'unknown'); ?>
                                                   </span>
                                               </div>
                                               <div><strong>Atlas:</strong>
                                                   <span class="status-btn status-<?php echo $summaries[$device['id']]['atlas_registered'] ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
                                                       <?php echo $summaries[$device['id']]['atlas_registered'] ? 'Yes' : 'No'; ?>
                                                   </span>
                                               </div>
                                               <div><strong>Pod:</strong>
                                                   <span class="status-btn status-<?php echo $summaries[$device['id']]['pod_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
                                                       <?php echo ucfirst($summaries[$device['id']]['pod_status'] ?? 'unknown'); ?>
                                                   </span>
                                               </div>
                                               <div><strong>XandMiner:</strong>
                                                   <span class="status-btn status-<?php echo $summaries[$device['id']]['xandminer_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
                                                       <?php echo ucfirst($summaries[$device['id']]['xandminer_status'] ?? 'unknown'); ?>
                                                   </span>
                                               </div>
                                               <div><strong>XandMinerD:</strong>
                                                   <span class="status-btn status-<?php echo $summaries[$device['id']]['xandminerd_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
                                                       <?php echo ucfirst($summaries[$device['id']]['xandminerd_status'] ?? 'unknown'); ?>
                                                   </span>
                                               </div>
                                           </div>
                                       <?php endif; ?>
                                   </td>
                                   <td>
                                       <?php if ($device['status'] === 'Not Initialized'): ?>
                                           <span class="status-btn status-not-initialized">Not Initialized</span>
                                       <?php else: ?>
                                           <div class="version-info">
                                               <div><strong>Controller:</strong>
                                                   <span class="version-value">
                                                       <?php echo htmlspecialchars($summaries[$device['id']]['chillxand_version'] ?? 'N/A'); ?>
                                                   </span>
                                               </div>
                                               <div><strong>Pod:</strong>
                                                   <span class="version-value">
                                                        <?php echo htmlspecialchars($summaries[$device['id']]['pod_version'] ?? 'N/A'); ?>
                                                   </span>
                                               </div>
                                               <div><strong>XandMiner:</strong>
                                                   <span class="version-value">
                                                        <?php echo htmlspecialchars($summaries[$device['id']]['xandminer_version'] ?? 'N/A'); ?>
                                                   </span>
                                               </div>
                                               <div><strong>XandMinerD:</strong>
                                                   <span class="version-value">
                                                        <?php echo htmlspecialchars($summaries[$device['id']]['xandminerd_version'] ?? 'N/A'); ?>
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
                                           <div style="font-size: 10px; color: #999;">
                                               <?php echo date('M j, H:i', strtotime($device['last_check'])); ?>
                                           </div>
                                       <?php else: ?>
                                           <div class="never-checked">Never checked</div>
                                       <?php endif; ?>
                                   </td>
                                   <td>
                                       <button type="button" class="action-btn-tiny action-edit"
                                               onclick="openEditModal(<?php echo $device['id']; ?>, '<?php echo htmlspecialchars($device['pnode_name'], ENT_QUOTES); ?>', '<?php echo htmlspecialchars($device['pnode_ip']); ?>')">Edit</button>
                                       <button type="button" class="action-btn-tiny action-delete"
                                               onclick="openDeleteModal(<?php echo $device['id']; ?>, '<?php echo htmlspecialchars($device['pnode_name'], ENT_QUOTES); ?>')">Delete</button>
                                       <button type="button" class="update-btn-controller"
                                               data-device-id="<?php echo $device['id']; ?>"
                                               data-device-ip="<?php echo htmlspecialchars($device['pnode_ip']); ?>"
                                               data-device-name="<?php echo htmlspecialchars($device['pnode_name'], ENT_QUOTES); ?>">
                                           Update Controller
                                       </button>
                                       <button type="button" class="update-btn-pod"
                                               data-device-id="<?php echo $device['id']; ?>"
                                               data-device-ip="<?php echo htmlspecialchars($device['pnode_ip']); ?>"
                                               data-device-name="<?php echo htmlspecialchars($device['pnode_name'], ENT_QUOTES); ?>">
                                           Update Pod
                                       </button>
                                   </td>
                               </tr>
                           <?php endforeach; ?>
                       </tbody>
                   </table>
               <?php endif; ?>

               <div style="margin-top: 20px; padding: 10px; background-color: #e9ecef; border-radius: 4px;">
                   <h4>Background Health Monitoring</h4>
                   <p><small>Device health status is automatically checked every 2 minutes by a background process.
                   Use the refresh button (↻) next to each device for immediate status updates. The status logs show
                   device connectivity checks, response times, and health status. Update buttons allow you to trigger
                   controller or pod updates on the remote devices.</small></p>
               </div>
           </div>
       </div>
   </div>

   <!-- Update Controller Modal -->
   <div id="updateControllerModal" class="modal">
       <div class="modal-content">
           <div class="modal-header">
               <h3>⚠️ Update Controller</h3>
               <span class="close" onclick="closeUpdateControllerModal()">&times;</span>
           </div>
           <div>
               <p><strong>Are you sure you want to update the controller for "<span id="update-controller-device-name"></span>"?</strong></p>
               <p>Device IP: <strong><span id="update-controller-device-ip"></span></strong></p>
               <p style="color: #dc3545; font-weight: bold;">⚠️ WARNING: The device may be temporarily unavailable during the update process!</p>
               <p>This will trigger an update process on the remote device.</p>
               <div class="modal-buttons">
                   <button type="button" class="modal-btn modal-btn-secondary" onclick="closeUpdateControllerModal()">Cancel</button>
                   <button type="button" class="modal-btn modal-btn-warning" onclick="confirmUpdateController()">Yes, Update Controller</button>
               </div>
           </div>
       </div>
   </div>

   <!-- Update Pod Modal -->
   <div id="updatePodModal" class="modal">
       <div class="modal-content">
           <div class="modal-header">
               <h3>⚠️ Update Pod</h3>
               <span class="close" onclick="closeUpdatePodModal()">&times;</span>
           </div>
           <div>
               <p><strong>Are you sure you want to update the pod for "<span id="update-pod-device-name"></span>"?</strong></p>
               <p>Device IP: <strong><span id="update-pod-device-ip"></span></strong></p>
               <p style="color: #dc3545; font-weight: bold;">⚠️ WARNING: The device may be temporarily unavailable during the update process!</p>
               <p>This will trigger an update process on the remote device.</p>
               <div class="modal-buttons">
                   <button type="button" class="modal-btn modal-btn-secondary" onclick="closeUpdatePodModal()">Cancel</button>
                   <button type="button" class="modal-btn modal-btn-warning" onclick="confirmUpdatePod()">Yes, Update Pod</button>
               </div>
           </div>
       </div>
   </div>

   <!-- Add Device Modal -->
   <div id="addModal" class="modal">
       <div class="modal-content">
           <div class="modal-header">
               <h3>Add New Device</h3>
               <span class="close" onclick="closeAddModal()">&times;</span>
           </div>
           <form id="addForm" method="POST" action="">
               <input type="hidden" name="action" value="add">
               <div class="modal-form-group">
                   <label for="add-pnode-name">Node Name:</label>
                   <input type="text" id="add-pnode-name" name="pnode_name" required>
               </div>
               <div class="modal-form-group">
                   <label for="add-pnode-ip">IP Address:</label>
                   <input type="text" id="add-pnode-ip" name="pnode_ip" required>
               </div>
               <div class="modal-buttons">
                   <button type="button" class="modal-btn modal-btn-secondary" onclick="closeAddModal()">Cancel</button>
                   <button type="button" class="modal-btn modal-btn-primary" onclick="submitAdd()">Add Device</button>
               </div>
           </form>
       </div>
   </div>

   <!-- Edit Device Modal -->
   <div id="editModal" class="modal">
       <div class="modal-content">
           <div class="modal-header">
               <h3>Edit Device</h3>
               <span class="close" onclick="closeEditModal()">&times;</span>
           </div>
           <form id="editForm" method="POST" action="">
               <input type="hidden" name="action" value="edit">
               <input type="hidden" id="edit-device-id" name="device_id">
               <div class="modal-form-group">
                   <label for="edit-pnode-name">Node Name:</label>
                   <input type="text" id="edit-pnode-name" name="pnode_name" required>
               </div>
               <div class="modal-form-group">
                   <label for="edit-pnode-ip">IP Address:</label>
                   <input type="text" id="edit-pnode-ip" name="pnode_ip" required>
               </div>
               <div class="modal-buttons">
                   <button type="button" class="modal-btn modal-btn-secondary" onclick="closeEditModal()">Cancel</button>
                   <button type="button" class="modal-btn modal-btn-primary" onclick="submitEdit()">Save Changes</button>
               </div>
           </form>
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
               <p style="color: #dc3545; font-weight: bold;">⚠️ This has dire results and cannot be undone!</p>
               <p>This will permanently remove the device and all its associated data from the system.</p>
               <div class="modal-buttons">
                   <button type="button" class="modal-btn modal-btn-secondary" onclick="closeDeleteModal()">Cancel</button>
                   <button type="button" class="modal-btn modal-btn-danger" onclick="submitDelete()">Delete Device</button>
               </div>
           </form>
       </div>
   </div>

<script>
        var pendingControllerUpdate = null;
        var pendingPodUpdate = null;
        var updateMonitors = {};

        document.addEventListener('DOMContentLoaded', function() {
            console.log('DOM loaded, initializing button handlers...');

            document.querySelectorAll('.update-btn-controller').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    const deviceId = this.getAttribute('data-device-id');
                    const deviceIp = this.getAttribute('data-device-ip');
                    const deviceName = this.getAttribute('data-device-name');
                    console.log('Controller update clicked:', deviceId, deviceIp, deviceName);
                    openUpdateControllerModal(deviceId, deviceIp, deviceName);
                });
            });

            document.querySelectorAll('.update-btn-pod').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    const deviceId = this.getAttribute('data-device-id');
                    const deviceIp = this.getAttribute('data-device-ip');
                    const deviceName = this.getAttribute('data-device-name');
                    console.log('Pod update clicked:', deviceId, deviceIp, deviceName);
                    openUpdatePodModal(deviceId, deviceIp, deviceName);
                });
            });

            console.log('Button handlers initialized successfully');
        });

        function refreshDeviceStatus(deviceId) {
            const statusElement = document.querySelector(`#status-${deviceId}`);
            const refreshBtn = document.querySelector(`#refresh-${deviceId}`);
            const lastCheckElement = document.querySelector(`#lastcheck-${deviceId}`);

            refreshBtn.disabled = true;
            refreshBtn.textContent = '⟳';

            fetch('manual_device_check.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `device_id=${deviceId}`
            })
            .then(response => {
                return response.text();
            })
            .then(responseText => {
                let data;
                try {
                    data = JSON.parse(responseText);
                } catch (parseError) {
                    console.error('JSON Parse Error:', parseError.message);
                    alert('Error parsing response. Please try again.');
                    refreshBtn.disabled = false;
                    refreshBtn.textContent = '↻';
                    return;
                }

                if (data.error) {
                    alert('Error: ' + data.error);
                } else {
                    let overallStatus = 'Unknown';
                    let statusClass = 'unknown';

                    if (data.status === 'Online') {
                        statusClass = 'online';
                        overallStatus = 'Online';
                    } else if (data.status === 'Offline') {
                        statusClass = 'offline';
                        overallStatus = 'Offline';
                    } else if (data.status === 'Error') {
                        statusClass = 'error';
                        overallStatus = 'Error';
                    } else {
                        statusClass = 'unknown';
                        overallStatus = data.status || 'Unknown';
                    }

                    // Update status
                    statusElement.innerHTML = `
                        <span class="status-btn status-${statusClass}">${overallStatus}</span>
                        <button class="refresh-btn" id="refresh-${deviceId}" onclick="refreshDeviceStatus(${deviceId})" title="Refresh status">↻</button>
                        <div class="status-age status-fresh">Just checked</div>
                        <div class="device-details">Response: ${data.response_time}ms</div>
                    `;

                    // Update health data if available
                    const healthElement = statusElement.nextElementSibling;
                    if (data.health_data && healthElement) {
                        const healthData = data.health_data;
                        healthElement.innerHTML = `
                            <div style="font-size: 10px; line-height: 1.3;">
                                <div><strong>Health:</strong>
                                    <span class="status-btn status-${healthData.health_status == 'pass' ? 'online' : 'offline'}" style="padding: 1px 4px; font-size: 9px;">
                                        ${healthData.health_status ? healthData.health_status.charAt(0).toUpperCase() + healthData.health_status.slice(1) : 'Unknown'}
                                    </span>
                                </div>
                                <div><strong>Atlas:</strong>
                                    <span class="status-btn status-${healthData.atlas_registered ? 'online' : 'offline'}" style="padding: 1px 4px; font-size: 9px;">
                                        ${healthData.atlas_registered ? 'Yes' : 'No'}
                                    </span>
                                </div>
                                <div><strong>Pod:</strong>
                                    <span class="status-btn status-${healthData.pod_status == 'active' ? 'online' : 'offline'}" style="padding: 1px 4px; font-size: 9px;">
                                        ${healthData.pod_status ? healthData.pod_status.charAt(0).toUpperCase() + healthData.pod_status.slice(1) : 'Unknown'}
                                    </span>
                                </div>
                                <div><strong>XandMiner:</strong>
                                    <span class="status-btn status-${healthData.xandminer_status == 'active' ? 'online' : 'offline'}" style="padding: 1px 4px; font-size: 9px;">
                                        ${healthData.xandminer_status ? healthData.xandminer_status.charAt(0).toUpperCase() + healthData.xandminer_status.slice(1) : 'Unknown'}
                                    </span>
                                </div>
                                <div><strong>XandMinerD:</strong>
                                    <span class="status-btn status-${healthData.xandminerd_status == 'active' ? 'online' : 'offline'}" style="padding: 1px 4px; font-size: 9px;">
                                        ${healthData.xandminerd_status ? healthData.xandminerd_status.charAt(0).toUpperCase() + healthData.xandminerd_status.slice(1) : 'Unknown'}
                                    </span>
                                </div>
                            </div>
                        `;
                    }

                    // Update versions if available
                    const versionsElement = healthElement ? healthElement.nextElementSibling : null;
                    if (data.version_data && versionsElement) {
                        const versionData = data.version_data;
                        versionsElement.innerHTML = `
                            <div class="version-info">
                                <div><strong>Controller:</strong>
                                    <span class="version-value">
                                        ${versionData.chillxand_version || 'N/A'}
                                    </span>
                                </div>
                                <div><strong>Pod:</strong>
                                    <span class="version-value">
                                        ${versionData.pod_version || 'N/A'}
                                    </span>
                                </div>
                                <div><strong>XandMiner:</strong>
                                    <span class="version-value">
                                        ${versionData.xandminer_version || 'N/A'}
                                    </span>
                                </div>
                                <div><strong>XandMinerD:</strong>
                                    <span class="version-value">
                                        ${versionData.xandminerd_version || 'N/A'}
                                    </span>
                                </div>
                            </div>
                        `;
                    }

                    // Update timestamp
                    lastCheckElement.innerHTML = `
                        <div class="status-fresh">Just now</div>
                        <div style="font-size: 10px; color: #999;">${data.timestamp}</div>
                    `;
                }
                refreshBtn.disabled = false;
                refreshBtn.textContent = '↻';
            })
            .catch(error => {
                console.error('Fetch Error:', error.message);
                alert('Failed to refresh status: ' + error.message);
                refreshBtn.disabled = false;
                refreshBtn.textContent = '↻';
            });
        }

        function openAddModal() {
            document.getElementById('add-pnode-name').value = '';
            document.getElementById('add-pnode-ip').value = '';
            document.getElementById('addModal').style.display = 'block';
        }

        function closeAddModal() {
            document.getElementById('addModal').style.display = 'none';
        }

        function openEditModal(deviceId, currentName, currentIp) {
            document.getElementById('edit-device-id').value = deviceId;
            document.getElementById('edit-pnode-name').value = currentName;
            document.getElementById('edit-pnode-ip').value = currentIp;
            document.getElementById('editModal').style.display = 'block';
        }

        function closeEditModal() {
            document.getElementById('editModal').style.display = 'none';
        }

        function openDeleteModal(deviceId, deviceName) {
            document.getElementById('delete-device-id').value = deviceId;
            document.getElementById('delete-device-name').textContent = deviceName;
            document.getElementById('deleteModal').style.display = 'block';
        }

        function closeDeleteModal() {
            document.getElementById('deleteModal').style.display = 'none';
        }

        function openUpdateControllerModal(deviceId, deviceIp, deviceName) {
            pendingControllerUpdate = { deviceId: deviceId, deviceIp: deviceIp, deviceName: deviceName };
            document.getElementById('update-controller-device-name').textContent = deviceName;
            document.getElementById('update-controller-device-ip').textContent = deviceIp;
            document.getElementById('updateControllerModal').style.display = 'block';
        }

        function closeUpdateControllerModal() {
            document.getElementById('updateControllerModal').style.display = 'none';
            pendingControllerUpdate = null;
        }

        function openUpdatePodModal(deviceId, deviceIp, deviceName) {
            pendingPodUpdate = { deviceId: deviceId, deviceIp: deviceIp, deviceName: deviceName };
            document.getElementById('update-pod-device-name').textContent = deviceName;
            document.getElementById('update-pod-device-ip').textContent = deviceIp;
            document.getElementById('updatePodModal').style.display = 'block';
        }

        function closeUpdatePodModal() {
            document.getElementById('updatePodModal').style.display = 'none';
            pendingPodUpdate = null;
        }

        function submitAdd() {
            document.getElementById('addForm').submit();
        }

        function submitEdit() {
            document.getElementById('editForm').submit();
        }

        function submitDelete() {
            document.getElementById('deleteForm').submit();
        }

        function confirmUpdateController() {
            if (!pendingControllerUpdate) return;

            const deviceId = pendingControllerUpdate.deviceId;
            const deviceIp = pendingControllerUpdate.deviceIp;
            const deviceName = pendingControllerUpdate.deviceName;

            closeUpdateControllerModal();

            console.log('User confirmed controller update for:', deviceName);

            const btn = document.querySelector(`[data-device-id="${deviceId}"].update-btn-controller`);
            if (!btn) {
                console.error('Could not find controller button for device', deviceId);
                alert('Error: Could not find update button');
                return;
            }

            const originalText = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Starting...';

            fetch('device_update.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=update_controller&device_id=${deviceId}&device_ip=${encodeURIComponent(deviceIp)}`
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return response.text();
            })
            .then(responseText => {
                console.log('Controller update raw response:', responseText);

                let data;
                try {
                    data = JSON.parse(responseText);
                } catch (jsonError) {
                    console.error('JSON parse error:', jsonError);
                    console.error('Response was:', responseText);
                    throw new Error(`Invalid JSON response from device_update.php: ${responseText.substring(0, 100)}...`);
                }

                if (data.success) {
                    if (data.status === 'no_update_needed') {
                        btn.textContent = 'No Update Needed';
                        btn.disabled = false;
                        setTimeout(() => {
                            btn.textContent = originalText;
                        }, 3000);
                        console.log(`Controller update: ${data.message}`);
                    } else if (data.status === 'update_initiated') {
                        btn.textContent = 'Update Started';
                        console.log(`Controller update started for ${deviceName}: ${data.message}`);
                        startUpdateMonitoring(deviceId, deviceIp, deviceName, 'controller', btn, originalText);
                    } else if (data.status === 'error_github_check') {
                        btn.textContent = 'GitHub Check Failed';
                        btn.disabled = false;
                        setTimeout(() => {
                            btn.textContent = originalText;
                        }, 5000);
                        console.error(`Controller update GitHub error for ${deviceName}: ${data.message}`);
                        alert(`Controller update failed for ${deviceName}\n\nGitHub Error: ${data.message}`);
                    } else if (data.status === 'exception') {
                        btn.textContent = 'Update Exception';
                        btn.disabled = false;
                        setTimeout(() => {
                            btn.textContent = originalText;
                        }, 5000);
                        console.error(`Controller update exception for ${deviceName}: ${data.message}`);
                        alert(`Controller update failed for ${deviceName}\n\nException: ${data.message}`);
                    } else {
                        btn.textContent = 'Update Response';
                        console.log(`Controller update response for ${deviceName}: Status=${data.status}, Message=${data.message}`);
                        setTimeout(() => {
                            btn.disabled = false;
                            btn.textContent = originalText;
                        }, 3000);
                    }
                } else {
                    alert(`Controller update failed for ${deviceName}.\n\nError: ${data.error || 'Unknown error'}`);
                    btn.disabled = false;
                    btn.textContent = originalText;
                }
            })
            .catch(error => {
                console.error('Controller update error:', error);
                alert(`Controller update failed for ${deviceName}.\n\nNetwork error: ${error.message}`);
                btn.disabled = false;
                btn.textContent = originalText;
            });
        }

        function confirmUpdatePod() {
            if (!pendingPodUpdate) return;

            const deviceId = pendingPodUpdate.deviceId;
            const deviceIp = pendingPodUpdate.deviceIp;
            const deviceName = pendingPodUpdate.deviceName;

            closeUpdatePodModal();

            console.log('User confirmed pod update for:', deviceName);

            const btn = document.querySelector(`[data-device-id="${deviceId}"].update-btn-pod`);
            if (!btn) {
                console.error('Could not find pod button for device', deviceId);
                alert('Error: Could not find update button');
                return;
            }

            const originalText = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Starting...';

            fetch('device_update.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=update_pod&device_id=${deviceId}&device_ip=${encodeURIComponent(deviceIp)}`
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return response.text();
            })
            .then(responseText => {
                console.log('Pod update raw response:', responseText);

                let data;
                try {
                    data = JSON.parse(responseText);
                } catch (jsonError) {
                    console.error('JSON parse error:', jsonError);
                    console.error('Response was:', responseText);
                    throw new Error(`Invalid JSON response: ${responseText.substring(0, 100)}...`);
                }

                if (data.success) {
                    if (data.status === 'no_update_needed') {
                        btn.textContent = 'No Update Needed';
                        btn.disabled = false;
                        setTimeout(() => {
                            btn.textContent = originalText;
                        }, 3000);
                        console.log(`Pod update: ${data.message}`);
                    } else if (data.status === 'update_initiated') {
                        btn.textContent = 'Update Started';
                        console.log(`Pod update started for ${deviceName}: ${data.message}`);
                        startUpdateMonitoring(deviceId, deviceIp, deviceName, 'pod', btn, originalText);
                    } else if (data.status === 'error_github_check') {
                        btn.textContent = 'GitHub Check Failed';
                        btn.disabled = false;
                        setTimeout(() => {
                            btn.textContent = originalText;
                        }, 5000);
                        console.error(`Pod update GitHub error for ${deviceName}: ${data.message}`);
                        alert(`Pod update failed for ${deviceName}\n\nGitHub Error: ${data.message}`);
                    } else if (data.status === 'exception') {
                        btn.textContent = 'Update Exception';
                        btn.disabled = false;
                        setTimeout(() => {
                            btn.textContent = originalText;
                        }, 5000);
                        console.error(`Pod update exception for ${deviceName}: ${data.message}`);
                        alert(`Pod update failed for ${deviceName}\n\nException: ${data.message}`);
                    } else {
                        btn.textContent = 'Update Response';
                        console.log(`Pod update response for ${deviceName}: Status=${data.status}, Message=${data.message}`);
                        setTimeout(() => {
                            btn.disabled = false;
                            btn.textContent = originalText;
                        }, 3000);
                    }
                } else {
                    alert(`Pod update failed for ${deviceName}.\n\nError: ${data.error || 'Unknown error'}`);
                    btn.disabled = false;
                    btn.textContent = originalText;
                }
            })
            .catch(error => {
                console.error('Pod update error:', error);
                alert(`Pod update failed for ${deviceName}.\n\nNetwork error: ${error.message}`);
                btn.disabled = false;
                btn.textContent = originalText;
            });
        }

        function startUpdateMonitoring(deviceId, deviceIp, deviceName, updateType, btn, originalText) {
            const monitorKey = `${deviceId}_${updateType}`;

            if (updateMonitors[monitorKey]) {
                clearInterval(updateMonitors[monitorKey].interval);
            }

            const monitor = {
                deviceId: deviceId,
                deviceIp: deviceIp,
                deviceName: deviceName,
                updateType: updateType,
                btn: btn,
                originalText: originalText,
                attemptCount: 0,
                maxAttempts: 60, // 120 × 5 seconds = 10 minutes
                lastLogLength: 0,
                consecutiveFailures: 0,
                maxConsecutiveFailures: 60, // Increased from 5 to 10 to be more tolerant
                updateStarted: false,
                restartDetected: false,
                postRestartAttempts: 0,
                maxPostRestartAttempts: 60, // Increased from 20 to 60 (5 minutes after restart)
                lastSuccessfulLogFetch: Date.now(),
                serviceRestartDetected: false, // New flag to track actual service restart
                restartConfirmed: false // New flag to confirm restart is real
            };

            if (updateType === 'controller') {
                monitor.interval = setInterval(() => {
                    checkControllerUpdateProgress(monitorKey, monitor);
                }, 10000);
            } else {
                monitor.interval = setInterval(() => {
                    checkUpdateProgress(monitorKey, monitor);
                }, 10000);
            }

            updateMonitors[monitorKey] = monitor;

            console.log(`Started monitoring ${updateType} update for ${deviceName}`);
        }

        function checkControllerUpdateProgress(monitorKey, monitor) {
            monitor.attemptCount++;

            const logUrl = `update_log_proxy.php?device_ip=${encodeURIComponent(monitor.deviceIp)}&update_type=${encodeURIComponent(monitor.updateType)}`;

            fetch(logUrl, {
                method: 'GET',
                headers: { 'Accept': 'text/plain' }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                return response.text();
            })
            .then(responseText => {
                let data;
                try {
                    data = JSON.parse(responseText);
                } catch (e) {
                    throw new Error('Invalid JSON response');
                }

                // Reset failure counters on successful response
                monitor.consecutiveFailures = 0;
                monitor.lastSuccessfulLogFetch = Date.now();

                // Handle status-based updates
                switch (data.status) {
                    case 'no_update_needed':
                        monitor.btn.textContent = 'No Update Needed';
                        finishUpdateMonitoring(monitorKey, monitor, 'no_update');
                        return;

                    case 'error_github_check':
                        monitor.btn.textContent = 'GitHub Check Failed';
                        finishUpdateMonitoring(monitorKey, monitor, 'failed');
                        return;

                    case 'error_starting':
                        monitor.btn.textContent = 'Start Error';
                        finishUpdateMonitoring(monitorKey, monitor, 'failed');
                        return;

                    case 'update_initiated':
                        monitor.btn.textContent = 'Update Started';
                        monitor.updateStarted = true;
                        break;

                    case 'in_progress':
                        monitor.btn.textContent = updateInProgressTimer(monitor);
                        monitor.updateStarted = true;
                        break;

                    case 'restarting':
                        if (!monitor.restartDetected) {
                            monitor.restartDetected = true;
                            monitor.restartConfirmed = true;
                            monitor.postRestartAttempts = 0;
                        }
                        monitor.btn.textContent = updateRestartTimer(monitor);
                        break;

                    case 'complete_success':
                        monitor.btn.textContent = 'Update Complete';
                        finishUpdateMonitoring(monitorKey, monitor, 'completed');
                        return;

                    case 'complete_warn':
                        monitor.btn.textContent = 'Complete (Warnings)';
                        monitor.lastWarningMessage = data.message || 'Update completed with warnings';
                        finishUpdateMonitoring(monitorKey, monitor, 'completed');
                        return;

                    case 'complete_fail':
                        monitor.btn.textContent = 'Update Failed';
                        monitor.lastErrorMessage = data.message || 'Update validation failed';
                        finishUpdateMonitoring(monitorKey, monitor, 'failed');
                        return;

                    default:
                        monitor.btn.textContent = `Status: ${data.status}`;
                        break;
                }

                // Check for overall timeout
                if (monitor.attemptCount >= monitor.maxAttempts) {
                    finishUpdateMonitoring(monitorKey, monitor, 'timeout');
                }

                // If we've detected restart and are in post-restart phase, check if we should continue
                if (monitor.restartDetected && monitor.postRestartAttempts >= monitor.maxPostRestartAttempts) {
                    console.log(`Post-restart monitoring complete for ${monitor.deviceName} ${monitor.updateType}`);
                    monitor.btn.textContent = 'Update Likely Complete';
                    finishUpdateMonitoring(monitorKey, monitor, 'post_restart_complete');
                }
            })
            .catch(error => {
                monitor.consecutiveFailures++;

                const timeSinceLastSuccess = Date.now() - monitor.lastSuccessfulLogFetch;
                const minutesSinceSuccess = Math.floor(timeSinceLastSuccess / 60000);

                console.log(`Connection error for ${monitor.deviceName}: ${error.message} (failure ${monitor.consecutiveFailures}, ${minutesSinceSuccess}m since last success)`);

                // Handle different phases of monitoring
                if (monitor.updateStarted && !monitor.restartDetected) {
                    // Try a direct health check to see if version changed (indicating completion)
                    if (monitor.initialVersion && monitor.consecutiveFailures >= 3) {
                        fetch(`http://${monitor.deviceIp}:3001/health`, {
                            method: 'GET',
                            timeout: 5000
                        })
                        .then(response => response.json())
                        .then(healthData => {
                            const currentVersion = healthData.chillxand_controller_version;
                            if (currentVersion && currentVersion !== monitor.initialVersion) {
                                console.log(`Health check: Version changed from ${monitor.initialVersion} to ${currentVersion} - update complete!`);
                                monitor.btn.textContent = 'Update Complete';
                                finishUpdateMonitoring(monitorKey, monitor, 'completed');
                                return;
                            }
                        })
                        .catch(() => {
                            // Health check also failed (expected if service is restarting)
                            console.log(`Health check failed during stuck update for ${monitor.deviceName}`);
                        });
                    }

                    // Update has started - only detect restart if we have strong indicators
                    if (monitor.serviceRestartDetected && monitor.consecutiveFailures >= 3) {
                        console.log(`Service restart confirmed for ${monitor.deviceName} - service is restarting`);
                        if (!monitor.restartDetected) {
                            monitor.restartDetected = true;
                            monitor.restartConfirmed = true;
                            monitor.postRestartAttempts = 0;
                        }
                        monitor.btn.textContent = updateRestartTimer(monitor);
                        monitor.consecutiveFailures = 0;
                    } else if (monitor.consecutiveFailures >= 8) {
                        console.log(`Possible restart detected for ${monitor.deviceName} (no log confirmation)`);
                        if (!monitor.restartDetected) {
                            monitor.restartDetected = true;
                            monitor.postRestartAttempts = 0;
                        }
                        monitor.btn.textContent = `Possible ${updateRestartTimer(monitor)}`;
                        monitor.consecutiveFailures = 0;
                    } else {
                        monitor.btn.textContent = `In Progress (${monitor.consecutiveFailures})`;
                    }
                } else if (monitor.restartDetected) {
                    // We're in restart phase - connection failures are expected
                    monitor.btn.textContent = updateRestartTimer(monitor);

                    // During restart, connection failures are completely normal
                    // Only exit on overall timeout, not connection failures
                } else {
                    // Update hasn't started yet - check if we should exit due to consecutive failures
                    if (monitor.consecutiveFailures >= monitor.maxConsecutiveFailures) {
                        console.log(`Pre-update connection failure for ${monitor.deviceName} - device may be unreachable`);
                        finishUpdateMonitoring(monitorKey, monitor, 'connection_failed');
                        return;
                    } else {
                        // Show the current failure count (but cap display at maxConsecutiveFailures - 1)
                        const displayCount = Math.min(monitor.consecutiveFailures, monitor.maxConsecutiveFailures - 1);
                        monitor.btn.textContent = `Connecting... (${displayCount})`;
                    }
                }

                // Check for overall timeout (this is our main exit condition)
                if (monitor.attemptCount >= monitor.maxAttempts) {
                    console.log(`Update monitoring timeout for ${monitor.deviceName} ${monitor.updateType} after 10 minutes`);

                    if (monitor.restartConfirmed) {
                        // We confirmed a restart happened, likely successful
                        console.log(`Restart confirmed for ${monitor.deviceName} - update likely completed successfully`);
                        monitor.btn.textContent = 'Update Likely Complete';
                        finishUpdateMonitoring(monitorKey, monitor, 'timeout_after_restart');
                    } else if (monitor.updateStarted) {
                        // Update started but unclear status
                        console.log(`Update started for ${monitor.deviceName} but status unclear`);
                        monitor.btn.textContent = 'Update Status Unknown';
                        finishUpdateMonitoring(monitorKey, monitor, 'timeout_after_update_start');
                    } else {
                        // Never got started properly
                        finishUpdateMonitoring(monitorKey, monitor, 'timeout');
                    }
                }
            });
        }

        function updateRestartTimer(monitor) {
            monitor.postRestartAttempts++;
            const totalSeconds = monitor.postRestartAttempts * 10;
            const minutesWaiting = Math.floor(totalSeconds / 60);
            const secondsWaiting = totalSeconds % 60;
            const timeDisplay = minutesWaiting > 0 ? `${minutesWaiting}m${secondsWaiting}s` : `${secondsWaiting}s`;
            return `Restarting (${timeDisplay})`;
        }

        function updateInProgressTimer(monitor) {
            if (!monitor.inProgressStart) {
                monitor.inProgressStart = monitor.attemptCount;
            }
            const inProgressAttempts = monitor.attemptCount - monitor.inProgressStart + 1;
            const totalSeconds = inProgressAttempts * 10; // 10-second intervals
            const minutesWaiting = Math.floor(totalSeconds / 60);
            const secondsWaiting = totalSeconds % 60;
            const timeDisplay = minutesWaiting > 0 ? `${minutesWaiting}m${secondsWaiting}s` : `${secondsWaiting}s`;
            return `In Progress (${timeDisplay})`;
        }

        function checkUpdateProgress(monitorKey, monitor) {
            monitor.attemptCount++;

            const logUrl = `update_log_proxy.php?device_ip=${encodeURIComponent(monitor.deviceIp)}&update_type=${encodeURIComponent(monitor.updateType)}`;

            fetch(logUrl, {
                method: 'GET',
                headers: { 'Accept': 'text/plain' }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                return response.text();
            })
            .then(logData => {
                // Reset failure counters on successful log fetch
                monitor.consecutiveFailures = 0;
                monitor.lastSuccessfulLogFetch = Date.now();

                const lines = logData.trim().split('\n').filter(line => line.trim());
                const currentLogLength = lines.length;

                if (lines.length > 0) {
                    const lastLine = lines[lines.length - 1].trim().toLowerCase();
                    const lastFewLines = lines.slice(-3).join(' ').toLowerCase();

                    // Mark that update has started
                    if (!monitor.updateStarted && (
                        lastLine.includes('downloading') ||
                        lastLine.includes('installing') ||
                        lastLine.includes('updating') ||
                        lastLine.includes('upgrade') ||
                        lastLine.includes('running installer'))) {
                        monitor.updateStarted = true;
                        console.log(`${monitor.updateType} update started for ${monitor.deviceName}`);
                    }

                    // Check for service restart indicators in logs
                    if (!monitor.serviceRestartDetected && (
                        lastLine.includes('reloading systemd daemon') ||
                        lastLine.includes('service will restart') ||
                        lastLine.includes('restarting service') ||
                        lastLine.includes('systemctl restart'))) {
                        monitor.serviceRestartDetected = true;
                        console.log(`Service restart initiated for ${monitor.deviceName}`);
                    }

                    // Check for completion patterns
                    if (lastFewLines.includes('no upgrade required') ||
                        lastFewLines.includes('no update required') ||
                        lastFewLines.includes('already up to date') ||
                        lastFewLines.includes('already up-to-date') ||
                        lastFewLines.includes('no updates available') ||
                        (lastLine.includes('latest') && lastLine.includes('version'))) {

                        monitor.btn.textContent = 'No Update Needed';
                        console.log(`${monitor.updateType} update completed - no upgrade required for ${monitor.deviceName}`);
                        finishUpdateMonitoring(monitorKey, monitor, 'no_update');
                        return;
                    }

                    // Check for successful completion
                    if (lastFewLines.includes('update completed') ||
                        lastFewLines.includes('pdate process finished') ||
                        lastFewLines.includes('update successful') ||
                        lastFewLines.includes('successfully updated') ||
                        lastFewLines.includes('upgrade completed') ||
                        lastFewLines.includes('installation completed') ||
                        lastFewLines.includes('service started successfully') ||
                        lastFewLines.includes('restart complete') ||
                        (lastLine.includes('started') && monitor.restartDetected)) {

                        monitor.btn.textContent = 'Update Complete';
                        console.log(`${monitor.updateType} update completed successfully for ${monitor.deviceName}`);
                        finishUpdateMonitoring(monitorKey, monitor, 'completed');
                        return;
                    }

                    // Check for errors
                    if (lastLine.includes('error') ||
                        lastLine.includes('failed') ||
                        lastLine.includes('exception') ||
                        (lastLine.includes('could not') && lastLine.includes('install'))) {

                        monitor.btn.textContent = 'Update Failed';
                        console.log(`${monitor.updateType} update failed for ${monitor.deviceName}: ${lastLine}`);
                        finishUpdateMonitoring(monitorKey, monitor, 'failed');
                        return;
                    }

                    // Update button text based on current activity
                    if (lastLine.includes('downloading') || lastLine.includes('download')) {
                        monitor.btn.textContent = 'Downloading...';
                    } else if (lastLine.includes('installing') || lastLine.includes('install')) {
                        monitor.btn.textContent = 'Installing...';
                    } else if (lastLine.includes('configuring') || lastLine.includes('configuration')) {
                        monitor.btn.textContent = 'Configuring...';
                    } else if (lastLine.includes('restarting') || lastLine.includes('restart')) {
                        monitor.btn.textContent = 'Restarting...';
                        monitor.restartDetected = true;
                        monitor.restartConfirmed = true;
                    } else if (lastLine.includes('updating') || lastLine.includes('upgrade')) {
                        monitor.btn.textContent = 'Updating...';
                    } else if (lastLine.includes('starting') || lastLine.includes('start')) {
                        monitor.btn.textContent = 'Starting Services...';
                    } else if (monitor.restartDetected) {
                        monitor.btn.textContent = `Post-Restart Check... (${monitor.postRestartAttempts})`;
                        monitor.postRestartAttempts++;
                    } else {
                        monitor.btn.textContent = 'In Progress...';
                    }

                    // Log new lines
                    if (currentLogLength > monitor.lastLogLength) {
                        const newLines = lines.slice(monitor.lastLogLength);
                        newLines.forEach(line => {
                            console.log(`[${monitor.deviceName} ${monitor.updateType}] ${line}`);
                        });
                        monitor.lastLogLength = currentLogLength;
                    }
                } else {
                    // No logs yet
                    if (monitor.updateStarted) {
                        monitor.btn.textContent = 'Checking Logs...';
                    } else {
                        monitor.btn.textContent = 'Waiting for Logs...';
                    }
                }

                // Check if we've exceeded max attempts
                if (monitor.attemptCount >= monitor.maxAttempts) {
                    console.log(`Update monitoring timeout for ${monitor.deviceName} ${monitor.updateType} after ${monitor.maxAttempts} attempts`);
                    finishUpdateMonitoring(monitorKey, monitor, 'timeout');
                }

                // If we've detected restart and are in post-restart phase, check if we should continue
                if (monitor.restartDetected && monitor.postRestartAttempts >= monitor.maxPostRestartAttempts) {
                    console.log(`Post-restart monitoring complete for ${monitor.deviceName} ${monitor.updateType}`);
                    monitor.btn.textContent = 'Update Likely Complete';
                    finishUpdateMonitoring(monitorKey, monitor, 'post_restart_complete');
                }
            })
            .catch(error => {
                monitor.consecutiveFailures++;

                const timeSinceLastSuccess = Date.now() - monitor.lastSuccessfulLogFetch;
                const minutesSinceSuccess = Math.floor(timeSinceLastSuccess / 60000);

                // More sophisticated failure detection
                const isConnectionError = error.message.includes('500') ||
                                        error.message.includes('503') ||
                                        error.message.includes('502') ||
                                        error.message.includes('Failed to fetch') ||
                                        error.message.includes('Network request failed') ||
                                        error.message.includes('Unable to connect') ||
                                        error.message.includes('Connection refused') ||
                                        error.message.toLowerCase().includes('connection') ||
                                        error.message.toLowerCase().includes('timeout') ||
                                        error.message.toLowerCase().includes('network');

                console.log(`Connection error for ${monitor.deviceName}: ${error.message} (failure ${monitor.consecutiveFailures}, ${minutesSinceSuccess}m since last success)`);

                // Handle different phases of monitoring with more intelligent logic
                if (monitor.updateStarted && !monitor.restartDetected) {
                    // Update has started - only detect restart if we have strong indicators
                    if (monitor.serviceRestartDetected && monitor.consecutiveFailures >= 3) {
                        // We saw restart in logs AND multiple connection failures
                        console.log(`Service restart confirmed for ${monitor.deviceName} - service is restarting`);
                        monitor.btn.textContent = 'pNode Restarting...';
                        monitor.restartDetected = true;
                        monitor.restartConfirmed = true;
                        monitor.consecutiveFailures = 0;
                    } else if (monitor.consecutiveFailures >= 8) {
                        // Many failures but no restart in logs - might be restart anyway
                        console.log(`Possible restart detected for ${monitor.deviceName} (no log confirmation)`);
                        monitor.btn.textContent = 'Possible Restart...';
                        monitor.restartDetected = true;
                        monitor.consecutiveFailures = 0;
                    } else {
                        monitor.btn.textContent = `Update in Progress... (checking ${monitor.consecutiveFailures})`;
                    }
                } else if (monitor.restartDetected) {
                    // We're in restart phase - connection failures are expected
                    monitor.postRestartAttempts++;
                    const totalSeconds = monitor.postRestartAttempts * 5;
                    const minutesWaiting = Math.floor(totalSeconds / 60);
                    const secondsWaiting = totalSeconds % 60;
                    const timeDisplay = minutesWaiting > 0 ? `${minutesWaiting}m${secondsWaiting}s` : `${secondsWaiting}s`;

                    if (monitor.consecutiveFailures <= 12) { // 1 minute
                        monitor.btn.textContent = `pNode Restarting... (${timeDisplay})`;
                    } else if (monitor.consecutiveFailures <= 36) { // 3 minutes
                        monitor.btn.textContent = `Still Restarting... (${timeDisplay})`;
                    } else if (monitor.consecutiveFailures <= 60) { // 5 minutes
                        monitor.btn.textContent = `Extended Restart... (${timeDisplay})`;
                    } else {
                        monitor.btn.textContent = `Long Restart... (${timeDisplay})`;
                    }

                    // During restart, connection failures are completely normal
                    // Only exit on overall timeout, not connection failures
                } else {
                    // Update hasn't started yet
                    if (monitor.consecutiveFailures >= monitor.maxConsecutiveFailures) {
                        console.log(`Pre-update connection failure for ${monitor.deviceName} - device may be unreachable`);
                        finishUpdateMonitoring(monitorKey, monitor, 'connection_failed');
                        return;
                    } else {
                        // Show the current failure count (but cap display at maxConsecutiveFailures - 1)
                        const displayCount = Math.min(monitor.consecutiveFailures, monitor.maxConsecutiveFailures - 1);
                        monitor.btn.textContent = `Connecting... (${displayCount})`;
                    }
                }

                // Check for overall timeout (this is our main exit condition)
                if (monitor.attemptCount >= monitor.maxAttempts) {
                    console.log(`Update monitoring timeout for ${monitor.deviceName} ${monitor.updateType} after 10 minutes`);

                    if (monitor.restartConfirmed) {
                        // We confirmed a restart happened, likely successful
                        console.log(`Restart confirmed for ${monitor.deviceName} - update likely completed successfully`);
                        monitor.btn.textContent = 'Update Likely Complete';
                        finishUpdateMonitoring(monitorKey, monitor, 'timeout_after_restart');
                    } else if (monitor.updateStarted) {
                        // Update started but unclear status
                        console.log(`Update started for ${monitor.deviceName} but status unclear`);
                        monitor.btn.textContent = 'Update Status Unknown';
                        finishUpdateMonitoring(monitorKey, monitor, 'timeout_after_update_start');
                    } else {
                        // Never got started properly
                        finishUpdateMonitoring(monitorKey, monitor, 'timeout');
                    }
                }
            });
        }

        function addUpdateStatusIcon(button, type, icon, message) {
            // Remove any existing status icon from the parent cell
            const parentCell = button.closest('td');
            const existingIcon = parentCell.querySelector(`.update-status-icon[data-button-id="${button.dataset.deviceId}-${button.classList.contains('update-btn-controller') ? 'controller' : 'pod'}"]`);
            if (existingIcon) {
                existingIcon.remove();
            }

            // Create new status icon
            const iconSpan = document.createElement('span');
            iconSpan.className = `update-status-icon update-status-${type}`;
            iconSpan.textContent = icon;
            iconSpan.title = message;
            iconSpan.dataset.buttonId = `${button.dataset.deviceId}-${button.classList.contains('update-btn-controller') ? 'controller' : 'pod'}`;
            iconSpan.style.cssText = `
                cursor: help;
                margin-left: 3px;
                display: inline;
                vertical-align: middle;
                font-size: 14px;
            `;

            // Insert icon right after the button (same line)
            button.insertAdjacentElement('afterend', iconSpan);

            console.log('Added icon after button:', button);
        }

        function finishUpdateMonitoring(monitorKey, monitor, reason) {
            if (monitor.interval) {
                clearInterval(monitor.interval);
            }

            delete updateMonitors[monitorKey];

            switch (reason) {
                case 'completed':
                    addUpdateStatusIcon(monitor.btn, 'success', '✅', 'Update completed successfully');
                    setTimeout(() => {
                        monitor.btn.textContent = monitor.originalText;
                        monitor.btn.disabled = false;
                        // Wait before checking device status after successful completion
                        setTimeout(() => {
                            refreshDeviceStatus(monitor.deviceId);
                        }, 1000); // Wait 1 seconds before first check
                    }, 3000);
                    break;
                case 'no_update':
                    addUpdateStatusIcon(monitor.btn, 'success', '✅', 'No update needed - already up to date');
                    setTimeout(() => {
                        monitor.btn.textContent = monitor.originalText;
                        monitor.btn.disabled = false;
                        // Quick refresh if no update was needed
                        setTimeout(() => {
                            refreshDeviceStatus(monitor.deviceId);
                        }, 3000);
                    }, 3000);
                    break;
                case 'failed':
                case 'connection_failed':
                    const errorMessage = monitor.lastErrorMessage || 'Update failed - check device status';
                    addUpdateStatusIcon(monitor.btn, 'error', '❌', errorMessage);
                    setTimeout(() => {
                        monitor.btn.textContent = monitor.originalText;
                        monitor.btn.disabled = false;
                        // Wait a bit in case device is recovering
                        setTimeout(() => {
                            refreshDeviceStatus(monitor.deviceId);
                        }, 10000);
                    }, 5000);
                    break;
                case 'complete_warn':
                    const warningMessage = monitor.lastWarningMessage || 'Update completed with warnings';
                    addUpdateStatusIcon(monitor.btn, 'warning', '⚠️', warningMessage);
                    setTimeout(() => {
                        monitor.btn.textContent = monitor.originalText;
                        monitor.btn.disabled = false;
                        setTimeout(() => {
                            refreshDeviceStatus(monitor.deviceId);
                        }, 3000);
                    }, 3000);
                    break;
                case 'complete_fail':
                    const failMessage = monitor.lastErrorMessage || 'Update validation failed';
                    addUpdateStatusIcon(monitor.btn, 'error', '❌', failMessage);
                    setTimeout(() => {
                        monitor.btn.textContent = monitor.originalText;
                        monitor.btn.disabled = false;
                        setTimeout(() => {
                            refreshDeviceStatus(monitor.deviceId);
                        }, 3000);
                    }, 3000);
                    break;
                case 'timeout':
                    addUpdateStatusIcon(monitor.btn, 'error', '❌', 'Update monitoring timed out - check device status manually');
                    // monitor.btn.textContent = 'Timed Out - Check Manually';
                    setTimeout(() => {
                        monitor.btn.textContent = monitor.originalText;
                        monitor.btn.disabled = false;
                        // Give extra time before refreshing after timeout
                        setTimeout(() => {
                            refreshDeviceStatus(monitor.deviceId);
                        }, 15000);
                    }, 5000);
                    break;
                case 'timeout_after_restart':
                    addUpdateStatusIcon(monitor.btn, 'warning', '⚠️', 'Update likely completed but monitoring timed out after restart');
                    // monitor.btn.textContent = 'Update Likely Complete';
                    setTimeout(() => {
                        monitor.btn.textContent = monitor.originalText;
                        monitor.btn.disabled = false;
                        // After restart was confirmed, wait longer before checking
                        setTimeout(() => {
                            refreshDeviceStatus(monitor.deviceId);
                        }, 30000); // Wait 30 seconds before checking
                    }, 4000);
                    break;
                case 'timeout_after_update_start':
                    addUpdateStatusIcon(monitor.btn, 'warning', '⚠️', 'Update started but final status unclear - check device manually');
                    // monitor.btn.textContent = 'Check Device Status';
                    setTimeout(() => {
                        monitor.btn.textContent = monitor.originalText;
                        monitor.btn.disabled = false;
                        // Update started but status unclear
                        setTimeout(() => {
                            refreshDeviceStatus(monitor.deviceId);
                        }, 20000); // Wait 20 seconds
                    }, 4000);
                    break;
                case 'post_restart_complete':
                    addUpdateStatusIcon(monitor.btn, 'success', '✅', 'Update likely completed successfully');
                    setTimeout(() => {
                        monitor.btn.textContent = monitor.originalText;
                        monitor.btn.disabled = false;
                        // Wait after restart to ensure device is fully ready
                        setTimeout(() => {
                            refreshDeviceStatus(monitor.deviceId);
                        }, 10000);
                    }, 3000);
                    break;
                default:
                    addUpdateStatusIcon(monitor.btn, 'warning', '⚠️', 'Update finished with unknown status');
                    monitor.btn.textContent = monitor.originalText;
                    monitor.btn.disabled = false;
                    setTimeout(() => {
                        refreshDeviceStatus(monitor.deviceId);
                    }, 5000);
            }

            console.log(`Finished monitoring ${monitor.updateType} update for ${monitor.deviceName} - reason: ${reason}`);
        }


        window.onclick = function(event) {
            const addModal = document.getElementById('addModal');
            const editModal = document.getElementById('editModal');
            const deleteModal = document.getElementById('deleteModal');
            const updateControllerModal = document.getElementById('updateControllerModal');
            const updatePodModal = document.getElementById('updatePodModal');

            if (event.target == addModal) {
                closeAddModal();
            }
            if (event.target == editModal) {
                closeEditModal();
            }
            if (event.target == deleteModal) {
                closeDeleteModal();
            }
            if (event.target == updateControllerModal) {
                closeUpdateControllerModal();
            }
            if (event.target == updatePodModal) {
                closeUpdatePodModal();
            }
        }

        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeAddModal();
                closeEditModal();
                closeDeleteModal();
                closeUpdateControllerModal();
                closeUpdatePodModal();
            }
        });
    </script>
</body>
</html>