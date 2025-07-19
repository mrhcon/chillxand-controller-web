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

// Fetch user's devices with status and last update
try {
    $stmt = $pdo->prepare("
        SELECT d.id, d.pnode_name, d.pnode_ip, d.registration_date,
               (SELECT MAX(ui.timestamp)
                FROM user_interactions ui
                WHERE ui.user_id = ? 
                AND ui.action IN ('device_status_check_success', 'device_status_check_failed')
                AND (ui.details LIKE CONCAT('%IP: ', d.pnode_ip, '%') OR ui.details LIKE CONCAT('%Device ID: ', d.id, '%'))) AS last_update
        FROM devices d
        WHERE d.username = ?
        ORDER BY d.registration_date DESC
    ");
    $stmt->execute([$_SESSION['user_id'], $_SESSION['username']]);
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Add status to each device
    $updated_devices = [];
    foreach ($devices as $device) {
        $status = pingDevice($device['pnode_ip'], $pdo, $_SESSION['user_id'], $_SESSION['username']);
        $device['status'] = $status['status'];
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
                                <th>Status</th>
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
                                        <span class="status-btn status-<?php echo strtolower($device['status']); ?>">
                                            <?php echo htmlspecialchars($device['status']); ?>
                                        </span>
                                    </td>
                                    <td><?php echo htmlspecialchars($device['last_update'] ?? 'N/A'); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
                <a href="devices.php"><button class="action-btn">Manage Devices</button></a>
            </div>
        </div>
    </div>
</body>
</html>