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
                // Add device
                $stmt = $pdo->prepare("INSERT INTO devices (username, pnode_name, pnode_ip, registration_date) VALUES (:username, :pnode_name, :pnode_ip, NOW())");
                $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
                $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
                $stmt->bindValue(':pnode_ip', $pnode_ip, PDO::PARAM_STR);
                $stmt->execute();

                logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_success', "Device: $pnode_name, IP: $pnode_ip");
                header("Location: dashboard.php");
                exit();
            }
        } catch (PDOException $e) {
            $error = "Error adding device: " . $e->getMessage();
            error_log($error);
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', $error);
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

    <style>
        .add-device-btn {
            background-color: #28a745;
            color: white;
            border: none;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            font-size: 20px;
            font-weight: bold;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background-color 0.3s ease;
            margin-left: 10px;
        }
        
        .add-device-btn:hover {
            background-color: #218838;
        }
        
        .devices-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        
        .devices-title {
            margin: 0;
            font-size: 1.5em;
        }
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
                <p>Last Login: <?php echo $last_login_display; ?></p>

                <!-- User Details Section -->
                <div style="margin-bottom: 30px;">
                    <h3>Your Details:</h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                        <div>
                            <p><strong>Username:</strong> <?php echo htmlspecialchars($user['username']); ?></p>
                            <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?></p>
                        </div>
                        <div>
                            <p><strong>Country:</strong> <?php echo htmlspecialchars($user['country']); ?></p>
                            <p><strong>Account Type:</strong> <?php echo $user['admin'] ? 'Administrator' : 'Standard User'; ?></p>
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
                                <th>Last Checked</th>
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
                this.updateInterval = 30000; // 30 seconds per device
                this.staggerDelay = 2000; // 2 seconds between device updates
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

                // Update last checked (7th column)
                const lastCheckedCell = row.cells[6];
                this.updateLastCheckedCell(lastCheckedCell, data);

                // Remove highlight after 2 seconds
                setTimeout(() => {
                    row.style.backgroundColor = '';
                }, 2000);
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

        function openAddModal() {
            document.getElementById('add-pnode-name').value = '';
            document.getElementById('add-pnode-ip').value = '';
            document.getElementById('addModal').style.display = 'block';
        }

        function closeAddModal() {
            document.getElementById('addModal').style.display = 'none';
        }

        function submitAdd() {
            document.getElementById('addForm').submit();
        }

        // Update your existing window.onclick function to include the addModal
        window.onclick = function(event) {
            const addModal = document.getElementById('addModal');
            if (event.target == addModal) {
                closeAddModal();
            }
        }

        // Update your existing keydown event listener to include closeAddModal
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeAddModal();
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
</body>
</html>