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
    <link rel="icon" type="image/x-icon" href="images/favicon.ico">
    <link rel="icon" type="image/png" sizes="32x32" href="images/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="images/favicon-16x16.png">
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
                    <!-- <li><button class="menu-button" onclick="window.location.href='device_logs.php'">Device Logs</button></li> -->
                    <?php if ($_SESSION['admin']): ?>
                        <li class="admin-section">
                            <strong>Admin</strong>
                            <ul>
                                <li><button class="menu-button admin-button active" onclick="window.location.href='admin_users.php'">Manage Users</button></li>
                                <li><button class="menu-button admin-button" onclick="window.location.href='admin_devices.php'">Manage Devices</button></li>
                            </ul>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
            <!-- Right Panel -->
            <div class="info-panel">
                <h2>Manage Users</h2>
                <?php if (isset($error)): ?>
                    <p class="error"><?php echo htmlspecialchars($error); ?></p>
                <?php endif; ?>

                <div class="devices-header">
                    <h3 class="devices-title">Users</h3>
                    <button type="button" class="add-device-btn" onclick="openAddModal()" title="Add New User">+</button>
                </div>
                <?php if (empty($users)): ?>
                    <p>No users found.</p>
                <?php else: ?>
                    <table class="user-table">
                        <thead>
                            <tr>
                                <th class="sortable-header" data-sort="username">
                                    Username
                                    <span class="sort-indicator"></span>
                                </th>
                                <th class="sortable-header" data-sort="email">
                                    Email
                                    <span class="sort-indicator"></span>
                                </th>
                                <th class="sortable-header" data-sort="first_name">
                                    First Name
                                    <span class="sort-indicator"></span>
                                </th>
                                <th class="sortable-header" data-sort="last_name">
                                    Last Name
                                    <span class="sort-indicator"></span>
                                </th>
                                <th class="sortable-header" data-sort="country">
                                    Country
                                    <span class="sort-indicator"></span>
                                </th>
                                <th class="sortable-header" data-sort="admin">
                                    Admin
                                    <span class="sort-indicator"></span>
                                </th>
                                <th class="sortable-header" data-sort="device_count">
                                    Device Count
                                    <span class="sort-indicator"></span>
                                </th>
                                <th>Actions</th>
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
                                    <td style="text-align: center;"><?php echo $user['admin'] ? '✓' : ''; ?></td>
                                    <td style="text-align: center;"><?php echo htmlspecialchars($user['device_count']); ?></td>
                                    <td>
                                        <div class="action-buttons-container">
                                            <div class="action-button-row">
                                                <button type="button" class="action-button edit"
                                                        onclick="openEditModal(<?php echo $user['id']; ?>, '<?php echo htmlspecialchars($user['username'], ENT_QUOTES); ?>', '<?php echo htmlspecialchars($user['email'], ENT_QUOTES); ?>', '<?php echo htmlspecialchars($user['first_name'] ?? '', ENT_QUOTES); ?>', '<?php echo htmlspecialchars($user['last_name'] ?? '', ENT_QUOTES); ?>', '<?php echo htmlspecialchars($user['country'] ?? '', ENT_QUOTES); ?>', <?php echo $user['admin'] ? 'true' : 'false'; ?>)">Edit</button>
                                            </div>
                                            <div class="action-button-row">
                                                <button type="button" class="action-button delete"
                                                        onclick="openDeleteModal(<?php echo $user['id']; ?>, '<?php echo htmlspecialchars($user['username'], ENT_QUOTES); ?>')">Delete</button>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Add User Modal -->
    <div id="addModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Add New User</h3>
                <span class="close" onclick="closeAddModal()">&times;</span>
            </div>
            <form id="addForm" method="POST" action="">
                <input type="hidden" name="action" value="add">
                <div class="modal-form-group">
                    <label for="add-username">Username:</label>
                    <input type="text" id="add-username" name="username" required>
                </div>
                <div class="modal-form-group">
                    <label for="add-email">Email:</label>
                    <input type="email" id="add-email" name="email" required>
                </div>
                <div class="modal-form-group">
                    <label for="add-first-name">First Name:</label>
                    <input type="text" id="add-first-name" name="first_name">
                </div>
                <div class="modal-form-group">
                    <label for="add-last-name">Last Name:</label>
                    <input type="text" id="add-last-name" name="last_name">
                </div>
                <div class="modal-form-group">
                    <label for="add-country">Country:</label>
                    <input type="text" id="add-country" name="country">
                </div>
                <div class="modal-form-group">
                    <label for="add-admin">Admin Privileges:</label>
                    <select id="add-admin" name="admin">
                        <option value="0">No</option>
                        <option value="1">Yes</option>
                    </select>
                </div>
                <div class="modal-buttons">
                    <button type="button" class="modal-btn modal-btn-secondary" onclick="closeAddModal()">Cancel</button>
                    <button type="button" class="modal-btn modal-btn-primary" onclick="submitAdd()">Add User</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Edit User Modal -->
    <div id="editModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Edit User</h3>
                <span class="close" onclick="closeEditModal()">&times;</span>
            </div>
            <form id="editForm" method="POST" action="">
                <input type="hidden" name="action" value="edit">
                <input type="hidden" id="edit-user-id" name="user_id">
                <div class="modal-form-group">
                    <label for="edit-username">Username:</label>
                    <input type="text" id="edit-username" name="username" required>
                </div>
                <div class="modal-form-group">
                    <label for="edit-email">Email:</label>
                    <input type="email" id="edit-email" name="email" required>
                </div>
                <div class="modal-form-group">
                    <label for="edit-first-name">First Name:</label>
                    <input type="text" id="edit-first-name" name="first_name">
                </div>
                <div class="modal-form-group">
                    <label for="edit-last-name">Last Name:</label>
                    <input type="text" id="edit-last-name" name="last_name">
                </div>
                <div class="modal-form-group">
                    <label for="edit-country">Country:</label>
                    <input type="text" id="edit-country" name="country">
                </div>
                <div class="modal-form-group">
                    <label for="edit-admin">Admin Privileges:</label>
                    <select id="edit-admin" name="admin">
                        <option value="0">No</option>
                        <option value="1">Yes</option>
                    </select>
                </div>
                <div class="modal-buttons">
                    <button type="button" class="modal-btn modal-btn-secondary" onclick="closeEditModal()">Cancel</button>
                    <button type="button" class="modal-btn modal-btn-primary" onclick="submitEdit()">Save Changes</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Delete User Modal -->
    <div id="deleteModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Delete User</h3>
                <span class="close" onclick="closeDeleteModal()">&times;</span>
            </div>
            <form id="deleteForm" method="POST" action="">
                <input type="hidden" name="action" value="delete">
                <input type="hidden" id="delete-user-id" name="user_id">
                <p><strong>Are you sure you want to delete the user "<span id="delete-user-name"></span>"?</strong></p>
                <p style="color: #dc3545; font-weight: bold;">⚠️ This action cannot be undone!</p>
                <p>This will permanently remove the user and may affect their associated devices.</p>
                <div class="modal-buttons">
                    <button type="button" class="modal-btn modal-btn-secondary" onclick="closeDeleteModal()">Cancel</button>
                    <button type="button" class="modal-btn modal-btn-danger" onclick="submitDelete()">Delete User</button>
                </div>
            </form>
        </div>
    </div>

    <style>
        /* Center modals properly on screen */
        .modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            display: none;
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }

        .modal.show {
            display: flex;
        }

        .modal-content {
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            max-width: 500px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
            position: relative;
            margin: 0;
            transform: none;
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }

        .modal-header h3 {
            margin: 0;
            color: #333;
        }

        .close {
            font-size: 24px;
            font-weight: bold;
            cursor: pointer;
            color: #999;
            line-height: 1;
        }

        .close:hover {
            color: #333;
        }

        .modal-form-group {
            margin-bottom: 15px;
        }

        .modal-form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #333;
        }

        .modal-form-group input,
        .modal-form-group select {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            box-sizing: border-box;
        }

        .modal-form-group input:focus,
        .modal-form-group select:focus {
            outline: none;
            border-color: #007bff;
            box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.25);
        }

        .modal-buttons {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid #eee;
        }

        .modal-btn {
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: background-color 0.2s;
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

        /* User Table Specific Styling */
        .user-table th:nth-child(6),
        .user-table td:nth-child(6) {
            width: 80px;
            max-width: 80px;
            text-align: center;
            padding: 8px;
        }

        .user-table th:nth-child(7),
        .user-table td:nth-child(7) {
            width: 120px;
            max-width: 120px;
            text-align: center;
            padding: 8px;
        }

        .user-table th:nth-child(8),
        .user-table td:nth-child(8) {
            width: 120px;
            max-width: 120px;
            text-align: center;
            padding: 8px;
            vertical-align: middle;
        }

        .action-buttons-container {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }

        .action-button-row {
            display: flex;
            justify-content: center;
        }

        .action-button {
            padding: 4px 8px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 500;
            min-width: 60px;
            transition: background-color 0.2s;
        }

        .action-button.edit {
            background-color: #007bff;
            color: white;
        }

        .action-button.edit:hover {
            background-color: #0056b3;
        }

        .action-button.delete {
            background-color: #dc3545;
            color: white;
        }

        .action-button.delete:hover {
            background-color: #c82333;
        }

        /* Make sure devices-header and add-device-btn styles are available */
        .devices-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .devices-title {
            margin: 0;
            color: #333;
        }

        .add-device-btn {
            background-color: #28a745;
            color: white;
            border: none;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            font-size: 15px;
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
    </style>

    <script>
        // Initialize table sorting when page loads
        document.addEventListener('DOMContentLoaded', function() {
            const table = document.querySelector('.user-table');
            if (table) {
                initializeTableSorting(table);
            }
        });

        // Table sorting functionality
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
                    case 'username':
                        aValue = a.cells[0].textContent.trim().toLowerCase();
                        bValue = b.cells[0].textContent.trim().toLowerCase();
                        break;

                    case 'email':
                        aValue = a.cells[1].textContent.trim().toLowerCase();
                        bValue = b.cells[1].textContent.trim().toLowerCase();
                        break;

                    case 'first_name':
                        aValue = a.cells[2].textContent.trim().toLowerCase();
                        bValue = b.cells[2].textContent.trim().toLowerCase();
                        // Handle N/A values
                        if (aValue === 'n/a') aValue = '';
                        if (bValue === 'n/a') bValue = '';
                        break;

                    case 'last_name':
                        aValue = a.cells[3].textContent.trim().toLowerCase();
                        bValue = b.cells[3].textContent.trim().toLowerCase();
                        // Handle N/A values
                        if (aValue === 'n/a') aValue = '';
                        if (bValue === 'n/a') bValue = '';
                        break;

                    case 'country':
                        aValue = a.cells[4].textContent.trim().toLowerCase();
                        bValue = b.cells[4].textContent.trim().toLowerCase();
                        // Handle N/A values
                        if (aValue === 'n/a') aValue = '';
                        if (bValue === 'n/a') bValue = '';
                        break;

                    case 'admin':
                        // Admin column: checkmark = 1, empty = 0
                        aValue = a.cells[5].textContent.trim() === '✓' ? 1 : 0;
                        bValue = b.cells[5].textContent.trim() === '✓' ? 1 : 0;
                        return direction === 'asc' ? aValue - bValue : bValue - aValue;

                    case 'device_count':
                        aValue = parseInt(a.cells[6].textContent.trim()) || 0;
                        bValue = parseInt(b.cells[6].textContent.trim()) || 0;
                        return direction === 'asc' ? aValue - bValue : bValue - aValue;

                    default:
                        aValue = a.cells[0].textContent.trim().toLowerCase();
                        bValue = b.cells[0].textContent.trim().toLowerCase();
                }

                // String comparison for most columns
                if (aValue < bValue) return direction === 'asc' ? -1 : 1;
                if (aValue > bValue) return direction === 'asc' ? 1 : -1;
                return 0;
            });

            // Re-append sorted rows
            rows.forEach(row => tbody.appendChild(row));
        }

        function openAddModal() {
            document.getElementById('add-username').value = '';
            document.getElementById('add-email').value = '';
            document.getElementById('add-first-name').value = '';
            document.getElementById('add-last-name').value = '';
            document.getElementById('add-country').value = '';
            document.getElementById('add-admin').value = '0';
            document.getElementById('addModal').style.display = 'flex';
        }

        function closeAddModal() {
            document.getElementById('addModal').style.display = 'none';
        }

        function openEditModal(userId, username, email, firstName, lastName, country, isAdmin) {
            document.getElementById('edit-user-id').value = userId;
            document.getElementById('edit-username').value = username;
            document.getElementById('edit-email').value = email;
            document.getElementById('edit-first-name').value = firstName || '';
            document.getElementById('edit-last-name').value = lastName || '';
            document.getElementById('edit-country').value = country || '';
            document.getElementById('edit-admin').value = isAdmin ? '1' : '0';
            document.getElementById('editModal').style.display = 'flex';
        }

        function closeEditModal() {
            document.getElementById('editModal').style.display = 'none';
        }

        function openDeleteModal(userId, username) {
            document.getElementById('delete-user-id').value = userId;
            document.getElementById('delete-user-name').textContent = username;
            document.getElementById('deleteModal').style.display = 'flex';
        }

        function closeDeleteModal() {
            document.getElementById('deleteModal').style.display = 'none';
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

        // Close modal when clicking outside of it
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

        // Close modal with Escape key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeAddModal();
                closeEditModal();
                closeDeleteModal();
            }
        });
    </script>
</body>
</html>