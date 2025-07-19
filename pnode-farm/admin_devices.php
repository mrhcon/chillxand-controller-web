<?php
session_start();
require_once 'db_connect.php';
require_once 'functions.php';

// Check if user is logged in and has admin privileges
if (!isset($_SESSION['user_id']) || !isset($_SESSION['admin']) || !$_SESSION['admin']) {
    header("Location: login.php");
    exit();
}

// Fetch all devices
try {
    $stmt = $pdo->prepare("
        SELECT id, username, pnode_name, pnode_ip, registration_date 
        FROM devices 
        ORDER BY username, registration_date DESC
    ");
    $stmt->execute();
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Error fetching devices: " . $e->getMessage();
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_devices_fetch_failed', $error);
}

// Log page access
logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_devices_access');
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - Devices</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="console-container">
        <!-- Top Bar Header -->
        <div class="top-bar">
            <h1>Network Management Console</h1>
            <div class="user-info">
                <span>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
                <a href="logout.php" class="logout-btn">Logout</a>
            </div>
        </div>
        <!-- Main Content -->
        <div class="main-content">
            <!-- Left Menu -->
            <div class="menu-column">
                <ul>
                    <li><button class="menu-button" onclick="window.location.href='dashboard.php'">Dashboard</button></li>
                    <li><button class="menu-button" onclick="window.location.href='devices.php'">Manage Devices</button></li>
                    <li><button class="menu-button" onclick="window.location.href='device_logs.php'">Device Logs</button></li>
                    <?php if ($_SESSION['admin']): ?>
                        <li class="admin-section">
                            <strong>Admin</strong>
                            <ul>
                                <li><button class="menu-button admin-button" onclick="window.location.href='admin_users.php'">Users</button></li>
                                <li><button class="menu-button admin-button active" onclick="window.location.href='admin_devices.php'">Devices</button></li>
                            </ul>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
            <!-- Right Panel -->
            <div class="info-panel">
                <h2>All Devices</h2>
                <?php if (isset($error)): ?>
                    <p class="error"><?php echo htmlspecialchars($error); ?></p>
                <?php endif; ?>
                <?php if (empty($devices)): ?>
                    <p>No devices found.</p>
                <?php else: ?>
                    <table class="device-table">
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Node Name</th>
                                <th>IP Address</th>
                                <th>Registration Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($devices as $device): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($device['username']); ?></td>
                                    <td><a href="device_details.php?device_id=<?php echo $device['id']; ?>"><?php echo htmlspecialchars($device['pnode_name']); ?></a></td>
                                    <td><?php echo htmlspecialchars($device['pnode_ip']); ?></td>
                                    <td><?php echo htmlspecialchars($device['registration_date']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
                <button type="button" class="action-btn reserved-btn">Reserved for Future Use</button>
            </div>
        </div>
    </div>
</body>
</html>