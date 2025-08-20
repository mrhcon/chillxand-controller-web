<?php
session_start();
require_once 'db_connect.php';
require_once 'functions.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Fetch admin status
try {
    $stmt = $pdo->prepare("SELECT admin FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    $_SESSION['admin'] = $user['admin'];
} catch (PDOException $e) {
    $error = "Error fetching user details: " . $e->getMessage();
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'user_fetch_failed', $error);
}

// Fetch devices for filter
try {
    $stmt = $pdo->prepare("SELECT pnode_name, pnode_ip FROM devices WHERE username = ? ORDER BY pnode_name");
    $stmt->execute([$_SESSION['username']]);
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Error fetching devices: " . $e->getMessage();
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_fetch_failed', $error);
}

// Handle search and filter
$search = isset($_POST['search']) ? trim($_POST['search']) : '';
$device_filter = isset($_POST['device_filter']) ? trim($_POST['device_filter']) : '';

$where_conditions = [];
$params = [];
$param_types = "";

if (!empty($search)) {
    $where_conditions[] = "(ui.action LIKE :search_action OR ui.details LIKE :search_details)";
    $params[':search_action'] = "%$search%";
    $params[':search_details'] = "%$search%";
    $param_types .= "ss";
}

if (!empty($device_filter)) {
    $where_conditions[] = "(ui.details LIKE :device_ip OR ui.details LIKE :device_name)";
    $params[':device_ip'] = "%IP: $device_filter%";
    $params[':device_name'] = "%Device: $device_filter%";
    $param_types .= "ss";
}

$where_clause = !empty($where_conditions) ? "WHERE " . implode(" AND ", $where_conditions) : "";

// Pagination parameters
$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$limit = isset($_GET['limit']) ? max(5, min((int)$_GET['limit'], 50)) : 10;
$offset = ($page - 1) * $limit;

// Fetch total log count
try {
    $count_sql = "
        SELECT COUNT(*) 
        FROM user_interactions ui
        LEFT JOIN devices d ON ui.user_id = :user_id_join AND (ui.details LIKE CONCAT('%IP: ', d.pnode_ip, '%') OR ui.details LIKE CONCAT('%Device: ', d.pnode_name, '%'))
        $where_clause
    ";
    $stmt = $pdo->prepare($count_sql);
    $params[':user_id_join'] = $_SESSION['user_id'];

    // Debug: Log query and parameters
    $emulated_count_query = "SELECT COUNT(*) 
                            FROM user_interactions ui
                            LEFT JOIN devices d ON ui.user_id = {$_SESSION['user_id']} AND (ui.details LIKE CONCAT('%IP: ', d.pnode_ip, '%') OR ui.details LIKE CONCAT('%Device: ', d.pnode_name, '%'))
                            $where_clause";
    error_log("Emulated count query: $emulated_count_query");
    error_log("Count query params: " . json_encode($params));

    // Bind parameters with explicit types
    foreach ($params as $key => $value) {
        $type = in_array($key, [':user_id_join']) ? PDO::PARAM_INT : PDO::PARAM_STR;
        $stmt->bindValue($key, $value, $type);
    }

    $stmt->execute();
    $total_logs = $stmt->fetchColumn();
    $total_pages = ceil($total_logs / $limit);
} catch (PDOException $e) {
    $error = "Error fetching log count: " . $e->getMessage();
    error_log("PDOException in log count: " . $e->getMessage());
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'logs_count_failed', $error);
}

// Fetch paginated logs
try {
    $sql = "
        SELECT d.pnode_name, d.pnode_ip, ui.action, ui.timestamp, ui.details
        FROM user_interactions ui
        LEFT JOIN devices d ON ui.user_id = :user_id_join AND (ui.details LIKE CONCAT('%IP: ', d.pnode_ip, '%') OR ui.details LIKE CONCAT('%Device: ', d.pnode_name, '%'))
        $where_clause
        ORDER BY ui.timestamp DESC
        LIMIT :limit OFFSET :offset
    ";
    $params[':user_id_join'] = $_SESSION['user_id'];
    $params[':limit'] = (int)$limit; // Ensure integer
    $params[':offset'] = (int)$offset; // Ensure integer

    // Debug: Log query and parameters
    $emulated_query = "SELECT d.pnode_name, d.pnode_ip, ui.action, ui.timestamp, ui.details
                       FROM user_interactions ui
                       LEFT JOIN devices d ON ui.user_id = {$_SESSION['user_id']} AND (ui.details LIKE CONCAT('%IP: ', d.pnode_ip, '%') OR ui.details LIKE CONCAT('%Device: ', d.pnode_name, '%'))
                       $where_clause
                       ORDER BY ui.timestamp DESC
                       LIMIT $limit OFFSET $offset";
    error_log("Emulated log query: $emulated_query");
    error_log("Log query params: " . json_encode($params));

    $stmt = $pdo->prepare($sql);
    foreach ($params as $key => $value) {
        $type = in_array($key, [':user_id_join', ':limit', ':offset']) ? PDO::PARAM_INT : PDO::PARAM_STR;
        $stmt->bindValue($key, $value, $type);
    }

    $stmt->execute();
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Error fetching logs: " . $e->getMessage();
    error_log("PDOException in log fetch: " . $e->getMessage());
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'logs_fetch_failed', $error);
}

// Log page access
logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_logs_access', "Page: $page, Limit: $limit, Search: $search, Device Filter: $device_filter");
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Logs</title>
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
                    <li><button class="menu-button" onclick="window.location.href='user_dashboard.php'">Dashboard</button></li>
                    <li><button class="menu-button active" onclick="window.location.href='device_logs.php'">Device Logs</button></li>
                    <?php if ($_SESSION['admin']): ?>
                        <li class="admin-section">
                            <strong>Admin</strong>
                            <ul>
                                <li><button class="menu-button admin-button" onclick="window.location.href='admin_users.php'">Manage Users</button></li>
                                <li><button class="menu-button admin-button" onclick="window.location.href='admin_devices.php'">Manage Devices</button></li>
                            </ul>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
            <!-- Right Panel -->
            <div class="info-panel">
                <h2>Device Logs</h2>
                <?php if (isset($error)): ?>
                    <p class="error"><?php echo htmlspecialchars($error); ?></p>
                <?php endif; ?>
                
                <!-- Search and Filter Form -->
                <form method="POST" action="">
                    <div class="form-group inline">
                        <label for="search">Search Logs:</label>
                        <input type="text" id="search" name="search" value="<?php echo htmlspecialchars($search); ?>" placeholder="Search by action or details">
                    </div>
                    <div class="form-group inline">
                        <label for="device_filter">Filter by Device:</label>
                        <select id="device_filter" name="device_filter">
                            <option value="">All Devices</option>
                            <?php foreach ($devices as $device): ?>
                                <option value="<?php echo htmlspecialchars($device['pnode_ip']); ?>" <?php echo $device_filter == $device['pnode_ip'] ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($device['pnode_name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <button type="submit">Apply Filter</button>
                </form>

                <!-- Logs Table -->
                <?php if (empty($logs)): ?>
                    <p>No logs found.</p>
                <?php else: ?>
                    <table class="log-table">
                        <thead>
                            <tr>
                                <th>Device Name</th>
                                <th>IP Address</th>
                                <th>Action</th>
                                <th>Timestamp</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($logs as $log): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($log['pnode_name'] ?? 'N/A'); ?></td>
                                    <td><?php echo htmlspecialchars($log['pnode_ip'] ?? 'N/A'); ?></td>
                                    <td><?php echo htmlspecialchars($log['action']); ?></td>
                                    <td><?php echo htmlspecialchars($log['timestamp']); ?></td>
                                    <td><?php echo htmlspecialchars($log['details'] ?? 'N/A'); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php if ($total_pages > 1): ?>
                        <div class="pagination-buttons">
                            <a href="?page=1&limit=<?php echo $limit; ?><?php echo $search ? '&search=' . urlencode($search) : ''; ?><?php echo $device_filter ? '&device_filter=' . urlencode($device_filter) : ''; ?>" class="action-btn-tiny action-first <?php echo $page == 1 ? 'disabled' : ''; ?>">First</a>
                            <a href="?page=<?php echo max(1, $page - 1); ?>&limit=<?php echo $limit; ?><?php echo $search ? '&search=' . urlencode($search) : ''; ?><?php echo $device_filter ? '&device_filter=' . urlencode($device_filter) : ''; ?>" class="action-btn-tiny action-prev <?php echo $page == 1 ? 'disabled' : ''; ?>">Previous</a>
                            <select onchange="window.location.href='?page=' + this.value + '&limit=<?php echo $limit; ?><?php echo $search ? '&search=' . urlencode($search) : ''; ?><?php echo $device_filter ? '&device_filter=' . urlencode($device_filter) : ''; ?>'" class="pagination-select">
                                <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                                    <option value="<?php echo $i; ?>" <?php echo $i == $page ? 'selected' : ''; ?>><?php echo $i; ?></option>
                                <?php endfor; ?>
                            </select>
                            <span>of <?php echo $total_pages; ?></span>
                            <a href="?page=<?php echo min($total_pages, $page + 1); ?>&limit=<?php echo $limit; ?><?php echo $search ? '&search=' . urlencode($search) : ''; ?><?php echo $device_filter ? '&device_filter=' . urlencode($device_filter) : ''; ?>" class="action-btn-tiny action-next <?php echo $page == $total_pages ? 'disabled' : ''; ?>">Next</a>
                            <a href="?page=<?php echo $total_pages; ?>&limit=<?php echo $limit; ?><?php echo $search ? '&search=' . urlencode($search) : ''; ?><?php echo $device_filter ? '&device_filter=' . urlencode($device_filter) : ''; ?>" class="action-btn-tiny action-last <?php echo $page == $total_pages ? 'disabled' : ''; ?>">Last</a>
                            <select onchange="window.location.href='?page=1&limit=' + this.value + '<?php echo $search ? '&search=' . urlencode($search) : ''; ?><?php echo $device_filter ? '&device_filter=' . urlencode($device_filter) : ''; ?>'" class="pagination-select">
                                <option value="5" <?php echo $limit == 5 ? 'selected' : ''; ?>>5</option>
                                <option value="10" <?php echo $limit == 10 ? 'selected' : ''; ?>>10</option>
                                <option value="20" <?php echo $limit == 20 ? 'selected' : ''; ?>>20</option>
                                <option value="50" <?php echo $limit == 50 ? 'selected' : ''; ?>>50</option>
                            </select>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>