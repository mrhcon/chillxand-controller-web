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
   stmt =pdo->prepare("SELECT username, email, first_name, last_name, country, admin FROM users WHERE id = ?");
   stmt->execute([$_SESSION['user_id']]);
   user =stmt->fetch(PDO::FETCH_ASSOC);
   _SESSION['admin'] =user['admin']; // Store admin status in session
} catch (PDOExceptione) {
   error = "Error fetching user details: " .e->getMessage();
    logInteraction($pdo,_SESSION['user_id'],_SESSION['username'], 'dashboard_access_failed',error);
}

// Fetch last login time
try {
   stmt =pdo->prepare("
        SELECT timestamp 
        FROM user_interactions 
        WHERE user_id = ? AND action = 'login_success' 
        ORDER BY timestamp DESC 
        LIMIT 1 OFFSET 1
    ");
   stmt->execute([$_SESSION['user_id']]);
   last_login =stmt->fetchColumn();
   last_login_display =last_login ? htmlspecialchars($last_login) : "No previous login recorded";
} catch (PDOExceptione) {
   error = "Error fetching last login: " .e->getMessage();
    logInteraction($pdo,_SESSION['user_id'],_SESSION['username'], 'last_login_fetch_failed',error);
}

// Fetch user's devices with enhanced status and order by node name
try {
   stmt =pdo->prepare("
        SELECT d.id, d.pnode_name, d.pnode_ip, d.registration_date
        FROM devices d
        WHERE d.username = ?
        ORDER BY d.pnode_name ASC
    ");
   stmt->execute([$_SESSION['username']]);
   devices =stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get latest statuses for all devices at once (super efficient!)
   device_ids = array_column($devices, 'id');
   cached_statuses = getLatestDeviceStatuses($pdo,device_ids);
    
    // Add cached status and health data to each device
   updated_devices = [];
   summaries = [];
    
    foreach ($devices asdevice) {
       device_id =device['id'];
       cached_status =cached_statuses[$device_id] ?? [
            'status' => 'Not Initialized',
            'is_stale' => true,
            'error_message' => 'Device has not been checked yet'
        ];
        
        // Add status from cache
       device['status'] =cached_status['status'];
       device['status_age'] =cached_status['age_minutes'];
       device['status_stale'] =cached_status['is_stale'];
       device['last_check'] =cached_status['check_time'];
       device['response_time'] =cached_status['response_time'];
       device['consecutive_failures'] =cached_status['consecutive_failures'];
       device['health_status'] =cached_status['health_status'];
        
        // Determine overall status (connectivity + health)
       overall_status = 'Unknown';
        if ($device['status'] === 'Online') {
            if ($device['health_status'] === 'pass') {
               overall_status = 'Healthy';
            } elseif ($device['health_status'] === 'fail') {
               overall_status = 'Online (Issues)';
            } else {
               overall_status = 'Online';
            }
        } elseif ($device['status'] === 'Offline') {
           overall_status = 'Offline';
        } else {
           overall_status =device['status'];
        }
       device['overall_status'] =overall_status;
        
        // Parse health data from cached data
       summaries[$device_id] = parseCachedDeviceHealth($cached_status);
        
       updated_devices[] =device;
    }
   devices =updated_devices;
    
} catch (PDOExceptione) {
   error = "Error fetching devices: " .e->getMessage();
    logInteraction($pdo,_SESSION['user_id'],_SESSION['username'], 'device_fetch_failed',error);
}

// Log dashboard access
logInteraction($pdo,_SESSION['user_id'],_SESSION['username'], 'dashboard_access');
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
        .status-healthy { background-color: #28a745; }
        .status-online-issues { background-color: #ffc107; color: #212529; }
        .status-not-initialized { background-color: #6c757d; }
        .device-status-details { font-size: 11px; color: #666; margin-top: 3px; }
        .status-age { font-size: 10px; color: #666; }
        .status-stale { color: #ff6600; }
        .status-fresh { color: #006600; }
        .never-checked { font-style: italic; color: #999; }
        .last-check-col { font-size: 11px; color: #666; }
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
                <h2>Welcome, <?php echo htmlspecialchars($user['first_name'] . ' ' .user['last_name']); ?>!</h2>
                <p>Last Login: <?php echolast_login_display; ?></p>
                
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
                            <p><strong>Account Type:</strong> <?php echouser['admin'] ? 'Administrator' : 'Standard User'; ?></p>
                        </div>
                    </div>
                </div>
                
                <?php if (isset($error)): ?>
                    <p class="error"><?php echo htmlspecialchars($error); ?></p>
                <?php endif; ?>
                
                <!-- Device Summary Cards -->
                <?php if (!empty($devices)): ?>
                    <?php
                   total_devices = count($devices);
                   online_devices = count(array_filter($devices, function($d) { returnd['status'] === 'Online'; }));
                   offline_devices = count(array_filter($devices, function($d) { returnd['status'] === 'Offline'; }));
                   healthy_devices = count(array_filter($devices, function($d) { returnd['overall_status'] === 'Healthy'; }));
                   issues_devices = count(array_filter($devices, function($d) { returnd['overall_status'] === 'Online (Issues)'; }));
                    ?>
                    <div class="dashboard-summary">
                        <div class="summary-card">
                            <h4>Total Devices</h4>
                            <div class="summary-number summary-total"><?php echototal_devices; ?></div>
                        </div>
                        <div class="summary-card">
                            <h4>Online</h4>
                            <div class="summary-number summary-online"><?php echoonline_devices; ?></div>
                        </div>
                        <div class="summary-card">
                            <h4>Healthy</h4>
                            <div class="summary-number summary-online"><?php echohealthy_devices; ?></div>
                        </div>
                        <div class="summary-card">
                            <h4>With Issues</h4>
                            <div class="summary-number summary-issues"><?php echoissues_devices; ?></div>
                        </div>
                        <div class="summary-card">
                            <h4>Offline</h4>
                            <div class="summary-number summary-offline"><?php echooffline_devices; ?></div>
                        </div>
                    </div>
                <?php endif; ?>

                <h3>Your Devices</h3>
                <?php if (empty($devices)): ?>
                    <p>No devices registered. <a href="devices.php">Add your first device</a> to get started!</p>
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
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($devices asdevice): ?>
                                <tr>
                                    <td><a href="device_details.php?device_id=<?php echodevice['id']; ?>"><?php echo htmlspecialchars($device['pnode_name']); ?></a></td>
                                    <td><?php echo htmlspecialchars($device['pnode_ip']); ?></td>
                                    <td><?php echo htmlspecialchars($device['registration_date']); ?></td>
                                    <td>
                                        <span class="status-btn status-<?php echo strtolower(str_replace(' ', '-',device['status'])); ?>">
                                            <?php echo htmlspecialchars($device['status']); ?>
                                        </span>
                                        <div class="status-age <?php echodevice['status_stale'] ? 'status-stale' : 'status-fresh'; ?>">
                                            <?php if ($device['last_check']): ?>
                                                <?php echodevice['status_age'] ? round($device['status_age']) . 'm ago' : 'Just now'; ?>
                                            <?php else: ?>
                                                Never checked
                                            <?php endif; ?>
                                        </div>
                                        <?php if ($device['response_time']): ?>
                                            <div class="device-status-details">Response: <?php echo round($device['response_time'] * 1000, 1); ?>ms</div>
                                        <?php endif; ?>
                                        <?php if ($device['consecutive_failures'] > 0): ?>
                                            <div class="device-status-details" style="color: #dc3545;">Failures: <?php echodevice['consecutive_failures']; ?></div>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($device['status'] === 'Not Initialized'): ?>
                                            <span class="status-btn status-not-initialized">Not Initialized</span>
                                        <?php else: ?>
                                            <div style="font-size: 10px; line-height: 1.3;">
                                                <div><strong>Health:</strong> 
                                                    <span class="status-btn status-<?php echosummaries[$device['id']]['health_status'] == 'pass' ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
                                                        <?php echo ucfirst($summaries[$device['id']]['health_status'] ?? 'unknown'); ?>
                                                    </span>
                                                </div>
                                                <div><strong>Atlas:</strong> 
                                                    <span class="status-btn status-<?php echosummaries[$device['id']]['atlas_registered'] ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
                                                        <?php echosummaries[$device['id']]['atlas_registered'] ? 'Yes' : 'No'; ?>
                                                    </span>
                                                </div>
                                                <div><strong>Pod:</strong> 
                                                    <span class="status-btn status-<?php echosummaries[$device['id']]['pod_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
                                                        <?php echo ucfirst($summaries[$device['id']]['pod_status'] ?? 'unknown'); ?>
                                                    </span>
                                                </div>
                                                <div><strong>XandMiner:</strong> 
                                                    <span class="status-btn status-<?php echosummaries[$device['id']]['xandminer_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
                                                        <?php echo ucfirst($summaries[$device['id']]['xandminer_status'] ?? 'unknown'); ?>
                                                    </span>
                                                </div>
                                                <div><strong>XandMinerD:</strong> 
                                                    <span class="status-btn status-<?php echosummaries[$device['id']]['xandminerd_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
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
                                    <td class="last-check-col">
                                        <?php if ($device['last_check']): ?>
                                            <div class="<?php echodevice['status_stale'] ? 'status-stale' : 'status-fresh'; ?>">
                                                <?php echodevice['status_age'] ? round($device['status_age']) . ' min ago' : 'Just now'; ?>
                                            </div>
                                            <div style="font-size: 10px; color: #999;">
                                                <?php echo date('M j, H:i', strtotime($device['last_check'])); ?>
                                            </div>
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
                const deviceRows = document.querySelectorAll('tbody tr');
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
                
                console.log(`Initialized status updater for{this.devices.length} devices`);
                
                // Start staggered updates
                this.startStaggeredUpdates();
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
                    // Stagger initial updates
                    setTimeout(() => {
                        this.updateDevice(device);
                        // Set up recurring updates for this device
                        setInterval(() => this.updateDevice(device), this.updateInterval);
                    }, index * this.staggerDelay);
                });
            }
            
            async updateDevice(device) {
                try {
                    console.log(`Updating device{device.id}...`);
                    
                    const response = await fetch(`ajax_device_status.php?device_id=${device.id}`);
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
                        console.log(`Device{device.id} updated successfully`);
                    } else {
                        console.error(`Error updating device{device.id}:`, data.error);
                    }
                } catch (error) {
                    console.error(`Failed to update device{device.id}:`, error);
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
                                       
                    console.log(`Summary updated:{totalDevices} total,{onlineDevices} online,{healthyDevices} healthy,{issuesDevices} issues,{offlineDevices} offline`);
                }
            }
            
            updateDeviceRow(device, data) {
                const row = device.row;
                
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
            }
            
            updateConnectivityCell(cell, data) {
                const statusClass = `status-${data.status.toLowerCase().replace(' ', '-')}`;
                const staleClass = data.status_stale ? 'status-stale' : 'status-fresh';
                const ageText = data.status_age ? Math.round(data.status_age) + 'm ago' : 'Just now';
                
                cell.innerHTML = `
                    <span class="status-btn{statusClass}">
                       {data.status}
                    </span>
                   {data.consecutive_failures > 0 ? `<div class="device-status-details" style="color: #dc3545;">Failures:{data.consecutive_failures}</div>` : ''}
                `;
            }
            
            updateHealthCell(cell, data) {
                if (data.status === 'Not Initialized') {
                    cell.innerHTML = '<span class="status-btn status-not-initialized">Not Initialized</span>';
                    return;
                }
                
                const summary = data.summary;
                cell.innerHTML = `
                    <div style="font-size: 10px; line-height: 1.3;">
                        <div><strong>Health:</strong> 
                            <span class="status-btn status-${summary.health_status == 'pass' ? 'online' : 'offline'}" style="padding: 1px 4px; font-size: 9px;">
                               {summary.health_status ? summary.health_status.charAt(0).toUpperCase() + summary.health_status.slice(1) : 'Unknown'}
                            </span>
                        </div>
                        <div><strong>Atlas:</strong> 
                            <span class="status-btn status-${summary.atlas_registered ? 'online' : 'offline'}" style="padding: 1px 4px; font-size: 9px;">
                               {summary.atlas_registered ? 'Yes' : 'No'}
                            </span>
                        </div>
                        <div><strong>Pod:</strong> 
                            <span class="status-btn status-${summary.pod_status == 'active' ? 'online' : 'offline'}" style="padding: 1px 4px; font-size: 9px;">
                               {summary.pod_status ? summary.pod_status.charAt(0).toUpperCase() + summary.pod_status.slice(1) : 'Unknown'}
                            </span>
                        </div>
                        <div><strong>XandMiner:</strong> 
                            <span class="status-btn status-${summary.xandminer_status == 'active' ? 'online' : 'offline'}" style="padding: 1px 4px; font-size: 9px;">
                               {summary.xandminer_status ? summary.xandminer_status.charAt(0).toUpperCase() + summary.xandminer_status.slice(1) : 'Unknown'}
                            </span>
                        </div>
                        <div><strong>XandMinerD:</strong> 
                            <span class="status-btn status-${summary.xandminerd_status == 'active' ? 'online' : 'offline'}" style="padding: 1px 4px; font-size: 9px;">
                               {summary.xandminerd_status ? summary.xandminerd_status.charAt(0).toUpperCase() + summary.xandminerd_status.slice(1) : 'Unknown'}
                            </span>
                        </div>
                    </div>
                `;
            }
            
            updateVersionsCell(cell, data) {
                if (data.status === 'Not Initialized') {
                    cell.innerHTML = '<span class="status-btn status-not-initialized">Not Initialized</span>';
                    return;
                }
                
                const summary = data.summary;
                cell.innerHTML = `
                    <div class="version-info">
                        <div><strong>Controller:</strong> 
                            <span class="version-value">
                               {summary.chillxand_version || 'N/A'}
                            </span>
                        </div>
                        <div><strong>Pod:</strong> 
                            <span class="version-value">
                               {summary.pod_version || 'N/A'}
                            </span>
                        </div>
                        <div><strong>XandMiner:</strong> 
                            <span class="version-value">
                               {summary.xandminer_version || 'N/A'}
                            </span>
                        </div>
                        <div><strong>XandMinerD:</strong> 
                            <span class="version-value">
                               {summary.xandminerd_version || 'N/A'}
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
                           {ageText}
                        </div>
                        <div style="font-size: 10px; color: #999;">
                           {formattedDate}
                        </div>
                       {data.response_time ? `<div class="device-status-details">Response:{Math.round(data.response_time * 1000)}ms</div>` : ''}                        
                    `;
                } else {
                    cell.innerHTML = '<div class="never-checked">Never checked</div>';
                }
            }
        }

        // Initialize the updater when page loads
        document.addEventListener('DOMContentLoaded', function() {
            if (document.querySelector('.device-table tbody tr')) {
                new DeviceStatusUpdater();
            }
        });
    </script>
</body>
</html>