<?php
// devices.php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
require_once 'db_connect.php';
require_once 'functions.php';

// CLI mock session for testing
if (PHP_SAPI === 'cli') {
    $_SESSION['user_id'] = 1; // Replace with a valid user ID for testing
    $_SESSION['username'] = 'test_user'; // Replace with a valid username
    $_SESSION['admin'] = 0; // Set to 1 for admin testing
    error_log("CLI mode: Mock session set with user_id={$_SESSION['user_id']}, username={$_SESSION['username']}, admin={$_SESSION['admin']}");
}

// Check if PDO is initialized
if (!isset($pdo) || $pdo === null) {
    $error = "Database connection error. Please contact the administrator.";
    error_log("PDO object is null in devices.php. Check db_connect.php configuration.");
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

// Fetch user's devices and summaries
try {
    $stmt = $pdo->prepare("SELECT id, pnode_name, pnode_ip, registration_date FROM devices WHERE username = :username OR :admin = 1 ORDER BY registration_date DESC");
    $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
    $stmt->bindValue(':admin', $_SESSION['admin'], PDO::PARAM_INT);
    $stmt->execute();
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
    error_log("Fetched " . count($devices) . " devices for user {$_SESSION['username']}");
    
    // Add status, initial logs, and JSON summaries to each device
    $limit = 3;
    $updated_devices = [];
    $summaries = [];
    foreach ($devices as $device) {
        // Validate IP address
        if (!filter_var($device['pnode_ip'], FILTER_VALIDATE_IP)) {
            $summaries[$device['id']] = ['error' => 'Invalid IP address.'];
            $device['status'] = 'Unknown';
            error_log("Invalid IP for device {$device['id']}: {$device['pnode_ip']}");
        } else {
            // Add status
            $status = pingDevice($device['pnode_ip'], $pdo, $_SESSION['user_id'], $_SESSION['username']);
            $device['status'] = $status['status'];
            
            // Fetch and parse JSON summary
            $raw_summary = fetchDeviceSummary($device['pnode_ip']);
            $summaries[$device['id']] = parseDeviceSummary($raw_summary, $device['pnode_ip']);
        }
        
        // Fetch initial logs
        $device_name_pattern = "%Device: {$device['pnode_name']}%";
        $ip_pattern = "%IP: {$device['pnode_ip']}%";
        $sql = "
            SELECT action, timestamp, details 
            FROM user_interactions 
            WHERE user_id = :user_id 
            AND (
                action IN ('device_status_check_success', 'device_status_check_failed', 'device_register_success', 'device_edit_success', 'device_delete_success')
                AND (details LIKE :device_name_pattern OR details LIKE :ip_pattern)
            )
            ORDER BY timestamp DESC 
            LIMIT :limit
        ";
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
        $stmt->bindValue(':device_name_pattern', $device_name_pattern, PDO::PARAM_STR);
        $stmt->bindValue(':ip_pattern', $ip_pattern, PDO::PARAM_STR);
        $stmt->bindValue(':limit', (int)$limit, PDO::PARAM_INT);
        
        // Debug: Log emulated query
        $emulated_query = "SELECT action, timestamp, details 
                           FROM user_interactions 
                           WHERE user_id = {$_SESSION['user_id']} 
                           AND (
                               action IN ('device_status_check_success', 'device_status_check_failed', 'device_register_success', 'device_edit_success', 'device_delete_success')
                               AND (details LIKE '$device_name_pattern' OR details LIKE '$ip_pattern')
                           )
                           ORDER BY timestamp DESC 
                           LIMIT $limit";
        error_log("Emulated initial logs query for device {$device['id']}: $emulated_query");
        
        $stmt->execute();
        $device['logs'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Count total logs
        $sql = "
            SELECT COUNT(*) 
            FROM user_interactions 
            WHERE user_id = :user_id 
            AND (
                action IN ('device_status_check_success', 'device_status_check_failed', 'device_register_success', 'device_edit_success', 'device_delete_success')
                AND (details LIKE :device_name_pattern OR details LIKE :ip_pattern)
            )
        ";
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
        $stmt->bindValue(':device_name_pattern', $device_name_pattern, PDO::PARAM_STR);
        $stmt->bindValue(':ip_pattern', $ip_pattern, PDO::PARAM_STR);
        
        // Debug: Log emulated query
        $emulated_count_query = "SELECT COUNT(*) 
                                FROM user_interactions 
                                WHERE user_id = {$_SESSION['user_id']} 
                                AND (
                                    action IN ('device_status_check_success', 'device_status_check_failed', 'device_register_success', 'device_edit_success', 'device_delete_success')
                                    AND (details LIKE '$device_name_pattern' OR details LIKE '$ip_pattern')
                                )";
        error_log("Emulated total logs query for device {$device['id']}: $emulated_count_query");
        
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
                $stmt = $pdo->prepare("INSERT INTO devices (username, pnode_name, pnode_ip, registration_date) VALUES (:username, :pnode_name, :pnode_ip, NOW())");
                $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
                $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
                $stmt->bindValue(':pnode_ip', $pnode_ip, PDO::PARAM_STR);
                $stmt->execute();
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
    <link rel="stylesheet" href="style.css">
    <style>
        .summary-container { margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; background: #f9f9f9; }
        .action-btn-tiny { padding: 5px 10px; margin-left: 10px; cursor: pointer; }
        .error { color: red; }
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
        function fetchLogs(deviceId, page, limit) {
            const logContainer = document.getElementById('log-container-' + deviceId);
            const moreButton = document.getElementById('more-items-' + deviceId);
            const pagination = document.getElementById('pagination-' + deviceId);

            fetch('get_device_logs.php', {
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

                let html = '<table class="log-table"><thead><tr><th>Action</th><th>Timestamp</th><th>Details</th></tr></thead><tbody>';
                if (data.logs.length === 0) {
                    html += '<tr><td colspan="3">No recent logs for this device.</td></tr>';
                } else {
                    data.logs.forEach(log => {
                        html += `<tr><td>${log.action}</td><td>${log.timestamp}</td><td>${log.details || 'N/A'}</td></tr>`;
                    });
                }
                html += '</tbody></table>';
                logContainer.innerHTML = html;

                pagination.innerHTML = '';
                if (data.total_pages > 1) {
                    const firstButton = `<a href="#" class="action-btn-tiny action-first ${data.current_page === 1 ? 'disabled' : ''}" onclick="fetchLogs(${deviceId}, 1, ${limit}); return false;">First</a>`;
                    const prevButton = `<a href="#" class="action-btn-tiny action-prev ${data.current_page === 1 ? 'disabled' : ''}" onclick="fetchLogs(${deviceId}, ${data.current_page - 1}, ${limit}); return false;">Previous</a>`;
                    const nextButton = `<a href="#" class="action-btn-tiny action-next ${data.current_page === data.total_pages ? 'disabled' : ''}" onclick="fetchLogs(${deviceId}, ${data.current_page + 1}, ${limit}); return false;">Next</a>`;
                    const lastButton = `<a href="#" class="action-btn-tiny action-last ${data.current_page === data.total_pages ? 'disabled' : ''}" onclick="fetchLogs(${deviceId}, ${data.total_pages}, ${limit}); return false;">Last</a>`;
                    let selectOptions = `<select onchange="fetchLogs(${deviceId}, this.value, ${limit})" class="pagination-select">`;
                    for (let i = 1; i <= data.total_pages; i++) {
                        selectOptions += `<option value="${i}" ${i === data.current_page ? 'selected' : ''}>${i}</option>`;
                    }
                    selectOptions += '</select>';
                    let limitOptions = `<select onchange="fetchLogs(${deviceId}, 1, this.value)" class="pagination-select">`;
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
                logContainer.innerHTML = '<p>Error fetching logs: ' + error.message + '</p>';
            });
        }
        function showMoreItems(deviceId) {
            fetchLogs(deviceId, 1, 10);
        }
    </script>
</head>
<body>
    <div class="console-container">
        <div class="top-bar">
            <h1>Network Management Console</h1>
            <div class="user-info">
                <span>Welcome, <?php echo htmlspecialchars($_SESSION['username'] ?? 'Guest'); ?></span>
                <a href="logout.php" class="logout-btn">Logout</a>
            </div>
        </div>
        <div class="main-content">
            <div class="menu-column">
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
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($devices as $device): ?>
                                <tr id="view-<?php echo $device['id']; ?>">
                                    <td><a href="device_details.php?device_id=<?php echo $device['id']; ?>"><?php echo htmlspecialchars($device['pnode_name']); ?></a></td>
                                    <td><?php echo htmlspecialchars($device['pnode_ip']); ?></td>
                                    <td><?php echo htmlspecialchars($device['registration_date']); ?></td>
                                    <td>
                                        <span class="status-btn status-<?php echo strtolower($device['status']); ?>">
                                            <?php echo htmlspecialchars($device['status']); ?>
                                        </span>
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
                                    <td colspan="5">
                                        <details>
                                            <summary>More Info</summary>
                                            <div class="summary-container">
                                                <h4>Device Summary (IP: <?php echo htmlspecialchars($device['pnode_ip']); ?>)</h4>
                                                <?php if ($summaries[$device['id']]['error']): ?>
                                                    <p class="error"><?php echo htmlspecialchars($summaries[$device['id']]['error']); ?></p>
                                                <?php else: ?>
                                                    <ul>
                                                        <?php if ($summaries[$device['id']]['uptime'] !== null): ?>
                                                            <li><strong>Uptime:</strong> <?php echo htmlspecialchars($summaries[$device['id']]['uptime']); ?></li>
                                                        <?php endif; ?>
                                                        <?php if ($summaries[$device['id']]['cpu_usage'] !== null): ?>
                                                            <li><strong>CPU Usage:</strong> <?php echo htmlspecialchars($summaries[$device['id']]['cpu_usage']); ?></li>
                                                        <?php endif; ?>
                                                        <?php if ($summaries[$device['id']]['memory_usage'] !== null): ?>
                                                            <li><strong>Memory Usage:</strong> <?php echo htmlspecialchars($summaries[$device['id']]['memory_usage']); ?></li>
                                                        <?php endif; ?>
                                                    </ul>
                                                <?php endif; ?>
                                            </div>
                                            <div id="log-container-<?php echo $device['id']; ?>">
                                                <table class="log-table">
                                                    <thead>
                                                        <tr>
                                                            <th>Action</th>
                                                            <th>Timestamp</th>
                                                            <th>Details</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <?php if (empty($device['logs'])): ?>
                                                            <tr>
                                                                <td colspan="3">No recent logs for this device.</td>
                                                            </tr>
                                                        <?php else: ?>
                                                            <?php foreach ($device['logs'] as $log): ?>
                                                                <tr>
                                                                    <td><?php echo htmlspecialchars($log['action']); ?></td>
                                                                    <td><?php echo htmlspecialchars($log['timestamp']); ?></td>
                                                                    <td><?php echo htmlspecialchars($log['details'] ?? 'N/A'); ?></td>
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
                                    <td colspan="5">
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
            </div>
        </div>
    </div>
</body>
</html>