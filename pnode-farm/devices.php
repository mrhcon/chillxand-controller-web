<?php
// devices.php - Updated to show device status logs instead of user interactions
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
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
            SELECT status, check_time, response_time, check_method, error_message, health_status
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
        .action-btn-tiny { padding: 5px 10px; margin-left: 10px; cursor: pointer; }
        .error { color: red; }
        .status-age { font-size: 10px; color: #666; }
        .status-stale { color: #ff6600; }
        .status-fresh { color: #006600; }
        .refresh-btn { 
            background-color: #17a2b8; 
            color: white; 
            border: none; 
            padding: 1px 4px; 
            font-size: 9px; 
            border-radius: 2px; 
            cursor: pointer; 
            margin-left: 3px;
            width: 14px;
            height: 14px;
            line-height: 1;
        }
        .refresh-btn:hover { background-color: #138496; }
        .device-details { font-size: 11px; color: #666; margin-top: 3px; }
        .status-not-initialized { background-color: #6c757d; }
        .status-healthy { background-color: #28a745; }
        .status-online-issues { background-color: #ffc107; color: #212529; }
        .last-check-col { font-size: 11px; color: #666; }
        .never-checked { font-style: italic; color: #999; }
        .status-log-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .status-log-table th, .status-log-table td { 
            border: 1px solid #ddd; 
            padding: 6px; 
            text-align: left; 
            font-size: 12px; 
        }
        .status-log-table th { background-color: #f8f9fa; }
        .log-status-online { color: #28a745; font-weight: bold; }
        .log-status-offline { color: #dc3545; font-weight: bold; }
        .log-status-error { color: #ffc107; font-weight: bold; }
    </style>
    <script>
        function toggleEdit(deviceId) {
            document.getElementById('view-' + deviceId).style.display = 'none';
            document.getElementById('edit-' + deviceId).style.display = 'table-row';
        }
        function cancelEdit(deviceId) {
            document.getElementById('view-' + deviceId).style.display = 'table-row';
            document.getElementById('edit-' + deviceId).style.display = 'none';
        }
        
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
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert('Error: ' + data.error);
                } else {
                    // Determine overall status (connectivity + health)
                    let overallStatus = 'Unknown';
                    let statusClass = 'unknown';
                    
                    if (data.status === 'Online') {
                        statusClass = 'online';
                        overallStatus = data.status;
                    } else if (data.status === 'Offline') {
                        overallStatus = 'Offline';
                        statusClass = 'offline';
                    } else {
                        overallStatus = data.status;
                        statusClass = data.status.toLowerCase().replace(' ', '-');
                    }
                    
                    statusElement.innerHTML = `
                        <span class="status-btn status-${statusClass}">${overallStatus}</span>
                        <button class="refresh-btn" id="refresh-${deviceId}" onclick="refreshDeviceStatus(${deviceId})" title="Refresh status">↻</button>
                        <div class="status-age status-fresh">Just checked</div>
                        <div class="device-details">Response: ${data.response_time}ms</div>
                        ${data.consecutive_failures > 0 ? `<div class="device-details" style="color: #dc3545;">Failures: ${data.consecutive_failures}</div>` : ''}
                    `;
                    
                    // Update health status column
                    const healthElement = statusElement.parentNode.nextElementSibling;
                    if (data.status === 'Online' && data.health_status) {
                        const healthClass = data.health_status === 'pass' ? 'online' : 'offline';
                        healthElement.innerHTML = `<span class="status-btn status-${healthClass}">${data.health_status.charAt(0).toUpperCase() + data.health_status.slice(1)}</span>`;
                    } else if (data.status === 'Not Initialized') {
                        healthElement.innerHTML = `<span class="status-btn status-not-initialized">Not Initialized</span>`;
                    } else {
                        healthElement.innerHTML = `<span class="status-btn status-not-initialized">Not Initialized</span>`;
                    }
                    
                    lastCheckElement.innerHTML = `
                        <div class="status-fresh">Just now</div>
                        <div style="font-size: 10px;">${data.timestamp}</div>
                    `;
                    
                    // Refresh the status logs section
                    fetchStatusLogs(deviceId, 1, 3);
                }
                refreshBtn.disabled = false;
                refreshBtn.textContent = '↻';
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Failed to refresh status');
                refreshBtn.disabled = false;
                refreshBtn.textContent = '↻';
            });
        }
        
        function fetchStatusLogs(deviceId, page, limit) {
            const logContainer = document.getElementById('log-container-' + deviceId);
            const moreButton = document.getElementById('more-items-' + deviceId);
            const pagination = document.getElementById('pagination-' + deviceId);

            fetch('get_device_status_logs.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `device_id=${deviceId}&page=${page}&limit=${limit}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    logContainer.innerHTML = '<p>Error: ' + data.error + '</p>';
                    return;
                }

                let html = '<table class="status-log-table"><thead><tr><th>Status</th><th>Check Time</th><th>Response Time</th><th>Health Status</th><th>Method</th></tr></thead><tbody>';
                if (data.logs.length === 0) {
                    html += '<tr><td colspan="5">No status logs for this device.</td></tr>';
                } else {
                    data.logs.forEach(log => {
                        const statusClass = log.status === 'Online' ? 'log-status-online' : 
                                          log.status === 'Offline' ? 'log-status-offline' : 'log-status-error';
                        const responseTime = log.response_time ? Math.round(log.response_time * 1000) + 'ms' : 'N/A';
                        const healthStatus = log.health_status || 'N/A';
                        const method = log.check_method || 'N/A';
                        
                        html += `<tr>
                            <td><span class="${statusClass}">${log.status}</span></td>
                            <td>${log.check_time}</td>
                            <td>${responseTime}</td>
                            <td>${healthStatus}</td>
                            <td>${method}</td>
                        </tr>`;
                    });
                }
                html += '</tbody></table>';
                logContainer.innerHTML = html;

                pagination.innerHTML = '';
                if (data.total_pages > 1) {
                    const firstButton = `<a href="#" class="action-btn-tiny action-first ${data.current_page === 1 ? 'disabled' : ''}" onclick="fetchStatusLogs(${deviceId}, 1, ${limit}); return false;">First</a>`;
                    const prevButton = `<a href="#" class="action-btn-tiny action-prev ${data.current_page === 1 ? 'disabled' : ''}" onclick="fetchStatusLogs(${deviceId}, ${data.current_page - 1}, ${limit}); return false;">Previous</a>`;
                    const nextButton = `<a href="#" class="action-btn-tiny action-next ${data.current_page === data.total_pages ? 'disabled' : ''}" onclick="fetchStatusLogs(${deviceId}, ${data.current_page + 1}, ${limit}); return false;">Next</a>`;
                    const lastButton = `<a href="#" class="action-btn-tiny action-last ${data.current_page === data.total_pages ? 'disabled' : ''}" onclick="fetchStatusLogs(${deviceId}, ${data.total_pages}, ${limit}); return false;">Last</a>`;
                    let selectOptions = `<select onchange="fetchStatusLogs(${deviceId}, this.value, ${limit})" class="pagination-select">`;
                    for (let i = 1; i <= data.total_pages; i++) {
                        selectOptions += `<option value="${i}" ${i === data.current_page ? 'selected' : ''}>${i}</option>`;
                    }
                    selectOptions += '</select>';
                    let limitOptions = `<select onchange="fetchStatusLogs(${deviceId}, 1, this.value)" class="pagination-select">`;
                    [5, 10, 20, 50].forEach(l => {
                        limitOptions += `<option value="${l}" ${l === limit ? 'selected' : ''}>${l}</option>`;
                    });
                    limitOptions += '</select>';
                    pagination.innerHTML = `${firstButton}${prevButton}${selectOptions}<span>of ${data.total_pages}</span>${nextButton}${lastButton}${limitOptions}`;
                }

                if (limit >= 5) {
                    moreButton.style.display = 'none';
                }
            })
            .catch(error => {
                logContainer.innerHTML = '<p>Error fetching status logs: ' + error.message + '</p>';
            });
        }
        function showMoreItems(deviceId) {
            fetchStatusLogs(deviceId, 1, 10);
        }
    </script>
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
                
                <h3>Add New Device</h3>
                <form method="POST" action="">
                    <input type="hidden" name="action" value="add">
                    <div class="form-group">
                        <label for="pnode_name">Node Name:</label>
                        <input type="text" id="pnode_name" name="pnode_name" required>
                    </div>
                    <div class="form-group">
                        <label for="pnode_ip">IP Address:</label>
                        <input type="text" id="pnode_ip" name="pnode_ip" required>
                    </div>
                    <button type="submit">Add Device</button>
                </form>

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
                                <th>Last Checked</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($devices as $device): ?>
                                <tr id="view-<?php echo $device['id']; ?>">
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
                                        <?php elseif ($device['health_status']): ?>
                                            <span class="status-btn status-<?php echo $device['health_status'] == 'pass' ? 'online' : 'offline'; ?>">
                                                <?php echo ucfirst($device['health_status']); ?>
                                            </span>
                                        <?php else: ?>
                                            <span class="status-btn status-not-initialized">Not Initialized</span>
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
                                        <button type="button" class="action-btn-tiny action-edit" onclick="toggleEdit(<?php echo $device['id']; ?>)">Edit</button>
                                        <form method="POST" action="" style="display:inline;" onsubmit="return confirm('Are you sure you want to delete this device?');">
                                            <input type="hidden" name="action" value="delete">
                                            <input type="hidden" name="device_id" value="<?php echo $device['id']; ?>">
                                            <button type="submit" class="action-btn-tiny action-delete">Delete</button>
                                        </form>
                                    </td>
                                </tr>
                                <tr>
                                    <td colspan="7">
                                        <details>
                                            <summary>More Info</summary>
                                            <div class="summary-container">
                                                <h4>Device Health (IP: <?php echo htmlspecialchars($device['pnode_ip']); ?>)</h4>
                                                <?php if ($summaries[$device['id']]['error']): ?>
                                                    <p class="error"><?php echo htmlspecialchars($summaries[$device['id']]['error']); ?></p>
                                                <?php else: ?>
                                                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
                                                        <div>
                                                            <h5>Service Status</h5>
                                                            <ul style="margin: 0; padding-left: 20px;">
                                                                <li><strong>Overall Health:</strong> 
                                                                    <span class="status-btn status-<?php echo $summaries[$device['id']]['health_status'] == 'pass' ? 'online' : 'offline'; ?>" style="padding: 2px 8px; font-size: 10px;">
                                                                        <?php echo ucfirst($summaries[$device['id']]['health_status'] ?? 'unknown'); ?>
                                                                    </span>
                                                                </li>
                                                                <li><strong>Atlas Registered:</strong> 
                                                                    <span class="status-btn status-<?php echo $summaries[$device['id']]['atlas_registered'] ? 'online' : 'offline'; ?>" style="padding: 2px 8px; font-size: 10px;">
                                                                        <?php echo $summaries[$device['id']]['atlas_registered'] ? 'Yes' : 'No'; ?>
                                                                    </span>
                                                                </li>
                                                                <li><strong>Pod:</strong> 
                                                                    <span class="status-btn status-<?php echo $summaries[$device['id']]['pod_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 2px 8px; font-size: 10px;">
                                                                        <?php echo ucfirst($summaries[$device['id']]['pod_status'] ?? 'unknown'); ?>
                                                                    </span>
                                                                </li>
                                                                <li><strong>XandMiner:</strong> 
                                                                    <span class="status-btn status-<?php echo $summaries[$device['id']]['xandminer_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 2px 8px; font-size: 10px;">
                                                                        <?php echo ucfirst($summaries[$device['id']]['xandminer_status'] ?? 'unknown'); ?>
                                                                    </span>
                                                                </li>
                                                                <li><strong>XandMinerD:</strong> 
                                                                    <span class="status-btn status-<?php echo $summaries[$device['id']]['xandminerd_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 2px 8px; font-size: 10px;">
                                                                        <?php echo ucfirst($summaries[$device['id']]['xandminerd_status'] ?? 'unknown'); ?>
                                                                    </span>
                                                                </li>
                                                            </ul>
                                                        </div>
                                                        <div>
                                                            <h5>System Info</h5>
                                                            <ul style="margin: 0; padding-left: 20px;">
                                                                <?php if ($summaries[$device['id']]['cpu_load_avg'] !== null): ?>
                                                                    <li><strong>CPU Load:</strong> <?php echo number_format($summaries[$device['id']]['cpu_load_avg'], 2); ?></li>
                                                                <?php endif; ?>
                                                                <?php if ($summaries[$device['id']]['memory_percent'] !== null): ?>
                                                                    <li><strong>Memory:</strong> <?php echo number_format($summaries[$device['id']]['memory_percent'], 1); ?>%</li>
                                                                <?php endif; ?>
                                                                <?php if ($summaries[$device['id']]['server_hostname']): ?>
                                                                    <li><strong>Hostname:</strong> <?php echo htmlspecialchars($summaries[$device['id']]['server_hostname']); ?></li>
                                                                <?php endif; ?>
                                                                <?php if ($summaries[$device['id']]['chillxand_version']): ?>
                                                                    <li><strong>ChillXand:</strong> <?php echo htmlspecialchars($summaries[$device['id']]['chillxand_version']); ?></li>
                                                                <?php endif; ?>
                                                                <?php if ($summaries[$device['id']]['node_version']): ?>
                                                                    <li><strong>Node Version:</strong> <?php echo htmlspecialchars($summaries[$device['id']]['node_version']); ?></li>
                                                                <?php endif; ?>
                                                            </ul>
                                                        </div>
                                                    </div>
                                                    <?php if ($summaries[$device['id']]['last_update']): ?>
                                                        <p><small>Health data last updated: <?php echo htmlspecialchars($summaries[$device['id']]['last_update']); ?></small></p>
                                                    <?php endif; ?>
                                                <?php endif; ?>
                                            </div>
                                            <h4>Recent Status Logs</h4>
                                            <div id="log-container-<?php echo $device['id']; ?>">
                                                <table class="status-log-table">
                                                    <thead>
                                                        <tr>
                                                            <th>Status</th>
                                                            <th>Check Time</th>
                                                            <th>Response Time</th>
                                                            <th>Health Status</th>
                                                            <th>Method</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <?php if (empty($device['logs'])): ?>
                                                            <tr>
                                                                <td colspan="5">No status logs for this device.</td>
                                                            </tr>
                                                        <?php else: ?>
                                                            <?php foreach ($device['logs'] as $log): ?>
                                                                <tr>
                                                                    <td>
                                                                        <span class="<?php echo $log['status'] === 'Online' ? 'log-status-online' : ($log['status'] === 'Offline' ? 'log-status-offline' : 'log-status-error'); ?>">
                                                                            <?php echo htmlspecialchars($log['status']); ?>
                                                                        </span>
                                                                    </td>
                                                                    <td><?php echo htmlspecialchars($log['check_time']); ?></td>
                                                                    <td><?php echo $log['response_time'] ? round($log['response_time'] * 1000) . 'ms' : 'N/A'; ?></td>
                                                                    <td><?php echo htmlspecialchars($log['health_status'] ?? 'N/A'); ?></td>
                                                                    <td><?php echo htmlspecialchars($log['check_method'] ?? 'N/A'); ?></td>
                                                                </tr>
                                                            <?php endforeach; ?>
                                                        <?php endif; ?>
                                                    </tbody>
                                                </table>
                                            </div>
                                            <?php if ($device['total_logs'] > $limit): ?>
                                                <button type="button" class="action-btn-tiny action-more" id="more-items-<?php echo $device['id']; ?>" onclick="showMoreItems(<?php echo $device['id']; ?>)">More Items</button>
                                            <?php endif; ?>
                                            <div id="pagination-<?php echo $device['id']; ?>" class="pagination-buttons"></div>
                                        </details>
                                    </td>
                                </tr>
                                <tr id="edit-<?php echo $device['id']; ?>" style="display:none;">
                                    <td colspan="7">
                                        <form method="POST" action="">
                                            <input type="hidden" name="action" value="edit">
                                            <input type="hidden" name="device_id" value="<?php echo $device['id']; ?>">
                                            <div class="form-group inline">
                                                <label for="pnode_name_<?php echo $device['id']; ?>">Node Name:</label>
                                                <input type="text" id="pnode_name_<?php echo $device['id']; ?>" name="pnode_name" value="<?php echo htmlspecialchars($device['pnode_name']); ?>" required>
                                            </div>
                                            <div class="form-group inline">
                                                <label for="pnode_ip_<?php echo $device['id']; ?>">IP Address:</label>
                                                <input type="text" id="pnode_ip_<?php echo $device['id']; ?>" name="pnode_ip" value="<?php echo htmlspecialchars($device['pnode_ip']); ?>" required>
                                            </div>
                                            <button type="submit" class="action-btn-tiny action-save">Save</button>
                                            <button type="button" class="action-btn-tiny action-cancel" onclick="cancelEdit(<?php echo $device['id']; ?>)">Cancel</button>
                                        </form>
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
                    device connectivity checks, response times, health status, and check methods used.</small></p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>