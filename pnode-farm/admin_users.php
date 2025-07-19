<?php
session_start();
require_once 'db_connect.php';
require_once 'functions.php';

// Check if user is logged in and has admin privileges
if (!isset($_SESSION['user_id']) || !isset($_SESSION['admin']) || !$_SESSION['admin']) {
    header("Location: login.php");
    exit();
}

// Fetch all users and their device counts
try {
    $stmt = $pdo->prepare("
        SELECT u.id, u.username, u.email, u.first_name, u.last_name, u.country, u.admin,
               (SELECT COUNT(*) FROM devices d WHERE d.username = u.username) AS device_count
        FROM users u
        ORDER BY u.username
    ");
    $stmt->execute();
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Error fetching users: " . $e->getMessage();
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_users_fetch_failed', $error);
}

// Log page access
logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_users_access');
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - Users</title>
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
                                <li><button class="menu-button admin-button active" onclick="window.location.href='admin_users.php'">Users</button></li>
                                <li><button class="menu-button admin-button" onclick="window.location.href='admin_devices.php'">Devices</button></li>
                            </ul>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
            <!-- Right Panel -->
            <div class="info-panel">
                <h2>Users</h2>
                <?php if (isset($error)): ?>
                    <p class="error"><?php echo htmlspecialchars($error); ?></p>
                <?php endif; ?>
                <?php if (empty($users)): ?>
                    <p>No users found.</p>
                <?php else: ?>
                    <table class="user-table">
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Email</th>
                                <th>First Name</th>
                                <th>Last Name</th>
                                <th>Country</th>
                                <th>Admin</th>
                                <th>Devices</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($users as $user): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($user['username']); ?></td>
                                    <td><?php echo htmlspecialchars($user['email']); ?></td>
                                    <td><?php echo htmlspecialchars($user['first_name'] ?? 'N/A'); ?></td>
                                    <td><?php echo htmlspecialchars($user['last_name'] ?? 'N/A'); ?></td>
                                    <td><?php echo htmlspecialchars($user['country'] ?? 'N/A'); ?></td>
                                    <td><?php echo $user['admin'] ? 'Yes' : 'No'; ?></td>
                                    <td><?php echo htmlspecialchars($user['device_count']); ?></td>
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