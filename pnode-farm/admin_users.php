function submitAdd() {
            document.getElementById('addForm').submit();
        }

        function validateAndSubmitAdd() {
            // Get form values
            const username = document.getElementById('add-username').value.trim();
            const email = document.getElementById('add-email').value.trim();
            const firstName = document.getElementById('add-first-name').value.trim();
            const lastName = document.getElementById('add-last-name').value.trim();
            const country = document.getElementById('add-country').value.trim();

            // Validate all required fields
            if (!username) {
                alert('Username is required.');
                document.getElementById('add-username').focus();
                return;
            }

            if (username.length > 50) {
                alert('Username must be 50 characters or less.');
                document.getElementById('add-username').focus();
                return;
            }

            if (!email) {
                alert('Email is required.');
                document.getElementById('add-email').focus();
                return;
            }

            // Basic email validation
            const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailPattern.test(email)) {
                alert('Please enter a valid email address.');
                document.getElementById('add-email').focus();
                return;
            }

            if (!firstName) {
                alert('First name is required.');
                document.getElementById('add-first-name').focus();
                return;
            }

            if (!lastName) {
                alert('Last name is required.');
                document.getElementById('add-last-name').focus();
                return;
            }

            if (!country) {
                alert('Country is required.');
                document.getElementById('add-country').focus();
                return;
            }

            // If all validation passes, submit the form
            document.getElementById('addForm').submit();
        }

        function submitEdit() {
            document.getElementById('editForm').submit();
        }

        function validateAndSubmitEdit() {
            // Get form values
            const email = document.getElementById('edit-email').value.trim();
            const firstName = document.getElementById('edit-first-name').value.trim();
            const lastName = document.getElementById('edit-last-name').value.trim();
            const country = document.getElementById('edit-country').value.trim();

            // Validate all required fields
            if (!email) {
                alert('Email is required.');
                document.getElementById('edit-email').focus();
                return;
            }

            // Basic email validation
            const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailPattern.test(email)) {
                alert('Please enter a valid email address.');
                document.getElementById('edit-email').focus();
                return;
            }

            if (!firstName) {
                alert('First name is required.');
                document.getElementById('edit-first-name').focus();
                return;
            }

            if (!lastName) {
                alert('Last name is required.');
                document.getElementById('edit-last-name').focus();
                return;
            }

            if (!country) {
                alert('Country is required.');
                document.getElementById('edit-country').focus();
                return;
            }

            // If all validation passes, submit the form
            document.getElementById('editForm').submit();
        }<?php
session_start();
require_once 'db_connect.php';
require_once 'functions.php';

// Check if user is logged in and has admin privileges
if (!isset($_SESSION['user_id']) || !isset($_SESSION['admin']) || !$_SESSION['admin']) {
    header("Location: login.php");
    exit();
}

// Handle add user
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'add') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $first_name = trim($_POST['first_name']);
    $last_name = trim($_POST['last_name']);
    $country = trim($_POST['country']);
    $admin = isset($_POST['admin']) ? (int)$_POST['admin'] : 0;

    // Validate all required fields
    if (empty($username)) {
        $error = "Username is required.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_add_failed', 'Empty username field');
    } elseif (empty($email)) {
        $error = "Email is required.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_add_failed', 'Empty email field');
    } elseif (empty($first_name)) {
        $error = "First name is required.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_add_failed', 'Empty first name field');
    } elseif (empty($last_name)) {
        $error = "Last name is required.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_add_failed', 'Empty last name field');
    } elseif (empty($country)) {
        $error = "Country is required.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_add_failed', 'Empty country field');
    } elseif (strlen($username) > 50) {
        $error = "Username must be 50 characters or less.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_add_failed', 'Username too long');
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email address.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_add_failed', 'Invalid email');
    } else {
        try {
            // Check for duplicate username
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = :username");
            $stmt->bindValue(':username', $username, PDO::PARAM_STR);
            $stmt->execute();
            if ($stmt->fetchColumn() > 0) {
                $error = "Username already exists.";
                logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_add_failed', 'Duplicate username');
            } else {
                // Check for duplicate email
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = :email");
                $stmt->bindValue(':email', $email, PDO::PARAM_STR);
                $stmt->execute();
                if ($stmt->fetchColumn() > 0) {
                    $error = "Email address already exists.";
                    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_add_failed', 'Duplicate email');
                } else {
                    // Generate random password
                    $random_password = bin2hex(random_bytes(8)); // 16 character random password
                    $hashed_password = password_hash($random_password, PASSWORD_DEFAULT);

                    // Insert new user (all fields are now required so no NULL values)
                    $stmt = $pdo->prepare("
                        INSERT INTO users (username, email, password, first_name, last_name, country, admin, registration_date) 
                        VALUES (:username, :email, :password, :first_name, :last_name, :country, :admin, NOW())
                    ");
                    $stmt->bindValue(':username', $username, PDO::PARAM_STR);
                    $stmt->bindValue(':email', $email, PDO::PARAM_STR);
                    $stmt->bindValue(':password', $hashed_password, PDO::PARAM_STR);
                    $stmt->bindValue(':first_name', $first_name, PDO::PARAM_STR);
                    $stmt->bindValue(':last_name', $last_name, PDO::PARAM_STR);
                    $stmt->bindValue(':country', $country, PDO::PARAM_STR);
                    $stmt->bindValue(':admin', $admin, PDO::PARAM_INT);
                    $stmt->execute();

                    $success = "User '$username' has been successfully created with temporary password: $random_password";
                    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_add_success', "Created user: $username, Email: $email, Admin: $admin");
                    
                    // Redirect to prevent re-submission
                    header("Location: admin_users.php?added=1&temp_pass=" . urlencode($random_password) . "&new_user=" . urlencode($username));
                    exit();
                }
            }
        } catch (PDOException $e) {
            $error = "Error creating user: " . $e->getMessage();
            error_log($error);
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_add_failed', $error);
        }
    }
}

// Handle edit user
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'edit') {
    $user_id = $_POST['user_id'];
    $email = trim($_POST['email']);
    $first_name = trim($_POST['first_name']);
    $last_name = trim($_POST['last_name']);
    $country = trim($_POST['country']);
    $admin = isset($_POST['admin']) ? (int)$_POST['admin'] : 0;

    // Validate all required fields
    if (empty($email)) {
        $error = "Email is required.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_edit_failed', 'Empty email field');
    } elseif (empty($first_name)) {
        $error = "First name is required.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_edit_failed', 'Empty first name field');
    } elseif (empty($last_name)) {
        $error = "Last name is required.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_edit_failed', 'Empty last name field');
    } elseif (empty($country)) {
        $error = "Country is required.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_edit_failed', 'Empty country field');
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email address.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_edit_failed', 'Invalid email');
    } else {
        try {
            // Check if user exists and get current username
            $stmt = $pdo->prepare("SELECT username FROM users WHERE id = :user_id");
            $stmt->bindValue(':user_id', $user_id, PDO::PARAM_INT);
            $stmt->execute();
            $existing_user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$existing_user) {
                $error = "User not found.";
                logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_edit_failed', 'User not found');
            } else {
                $username = $existing_user['username']; // Keep original username
                
                // Check for duplicate email (excluding current user)
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = :email AND id != :user_id");
                $stmt->bindValue(':email', $email, PDO::PARAM_STR);
                $stmt->bindValue(':user_id', $user_id, PDO::PARAM_INT);
                $stmt->execute();
                if ($stmt->fetchColumn() > 0) {
                    $error = "Email address already exists.";
                    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_edit_failed', 'Duplicate email');
                } else {
                    // Prevent admin from removing their own admin privileges
                    if ($user_id == $_SESSION['user_id'] && $admin == 0) {
                        $error = "You cannot remove your own admin privileges.";
                        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_edit_failed', 'Attempted to remove own admin privileges');
                    } else {
                        // Update user (excluding username, all fields are now required so no NULL values)
                        $stmt = $pdo->prepare("
                            UPDATE users 
                            SET email = :email, first_name = :first_name, 
                                last_name = :last_name, country = :country, admin = :admin 
                            WHERE id = :user_id
                        ");
                        $stmt->bindValue(':email', $email, PDO::PARAM_STR);
                        $stmt->bindValue(':first_name', $first_name, PDO::PARAM_STR);
                        $stmt->bindValue(':last_name', $last_name, PDO::PARAM_STR);
                        $stmt->bindValue(':country', $country, PDO::PARAM_STR);
                        $stmt->bindValue(':admin', $admin, PDO::PARAM_INT);
                        $stmt->bindValue(':user_id', $user_id, PDO::PARAM_INT);
                        $stmt->execute();

                        // If we're editing our own account, update session admin status
                        if ($user_id == $_SESSION['user_id']) {
                            $_SESSION['admin'] = $admin;
                        }

                        $success = "User '$username' has been successfully updated.";
                        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_edit_success', "Updated user ID: $user_id, Username: $username, Admin: $admin");
                        
                        // Redirect to prevent re-submission
                        header("Location: admin_users.php?edited=1");
                        exit();
                    }
                }
            }
        } catch (PDOException $e) {
            $error = "Error updating user: " . $e->getMessage();
            error_log($error);
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_edit_failed', $error);
        }
    }
}

// Handle delete user
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'delete') {
    if (!isset($_POST['user_id'])) {
        $error = "Missing user ID.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_delete_failed', 'Missing user ID');
    } else {
        $user_id = $_POST['user_id'];
        
        // Prevent admin from deleting themselves
        if ($user_id == $_SESSION['user_id']) {
            $error = "You cannot delete your own account.";
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_delete_failed', 'Attempted to delete own account');
        } else {
            try {
                // Get user details before deletion for logging
                $stmt = $pdo->prepare("SELECT username, email, first_name, last_name FROM users WHERE id = :user_id");
                $stmt->bindValue(':user_id', $user_id, PDO::PARAM_INT);
                $stmt->execute();
                $user_to_delete = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($user_to_delete) {
                    // Start transaction
                    $pdo->beginTransaction();

                    // Check if user has devices
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE username = :username");
                    $stmt->bindValue(':username', $user_to_delete['username'], PDO::PARAM_STR);
                    $stmt->execute();
                    $device_count = $stmt->fetchColumn();

                    if ($device_count > 0) {
                        // Delete all devices owned by this user first
                        $stmt = $pdo->prepare("DELETE FROM devices WHERE username = :username");
                        $stmt->bindValue(':username', $user_to_delete['username'], PDO::PARAM_STR);
                        $stmt->execute();
                        
                        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_devices_deleted_with_user', "Deleted $device_count devices for user: {$user_to_delete['username']}");
                    }

                    // Delete user interactions/logs for this user
                    $stmt = $pdo->prepare("DELETE FROM user_interactions WHERE user_id = :user_id");
                    $stmt->bindValue(':user_id', $user_id, PDO::PARAM_INT);
                    $stmt->execute();

                    // Finally, delete the user
                    $stmt = $pdo->prepare("DELETE FROM users WHERE id = :user_id");
                    $stmt->bindValue(':user_id', $user_id, PDO::PARAM_INT);
                    $stmt->execute();

                    // Commit transaction
                    $pdo->commit();

                    $success = "User '{$user_to_delete['username']}' has been successfully deleted.";
                    if ($device_count > 0) {
                        $success .= " Also deleted $device_count associated devices.";
                    }
                    
                    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_delete_success', "Deleted user: {$user_to_delete['username']} (ID: $user_id)");
                    
                    // Redirect to prevent re-submission
                    header("Location: admin_users.php?deleted=1");
                    exit();
                } else {
                    $error = "User not found.";
                    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_delete_failed', 'User not found');
                }
            } catch (PDOException $e) {
                // Rollback transaction on error
                if ($pdo->inTransaction()) {
                    $pdo->rollback();
                }
                
                $error = "Error deleting user: " . $e->getMessage();
                error_log($error);
                logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'admin_user_delete_failed', $error);
            }
        }
    }
}

// Check for success messages from redirects
if (isset($_GET['added']) && $_GET['added'] == '1') {
    $temp_password = $_GET['temp_pass'] ?? '';
    $new_username = $_GET['new_user'] ?? '';
    if ($temp_password && $new_username) {
        $success = "User '$new_username' has been successfully created with temporary password: $temp_password";
    } else {
        $success = "User has been successfully created.";
    }
}

if (isset($_GET['edited']) && $_GET['edited'] == '1') {
    $success = "User has been successfully updated.";
}

if (isset($_GET['deleted']) && $_GET['deleted'] == '1') {
    $success = "User has been successfully deleted.";
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
                <?php if (isset($success)): ?>
                    <p class="success"><?php echo htmlspecialchars($success); ?></p>
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
                    <label for="add-username">Username: <span style="color: red;">*</span></label>
                    <input type="text" id="add-username" name="username" required maxlength="50">
                </div>
                <div class="modal-form-group">
                    <label for="add-email">Email: <span style="color: red;">*</span></label>
                    <input type="email" id="add-email" name="email" required>
                </div>
                <div class="modal-form-group">
                    <label for="add-first-name">First Name: <span style="color: red;">*</span></label>
                    <input type="text" id="add-first-name" name="first_name" required>
                </div>
                <div class="modal-form-group">
                    <label for="add-last-name">Last Name: <span style="color: red;">*</span></label>
                    <input type="text" id="add-last-name" name="last_name" required>
                </div>
                <div class="modal-form-group">
                    <label for="add-country">Country: <span style="color: red;">*</span></label>
                    <input type="text" id="add-country" name="country" required>
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
                    <button type="button" class="modal-btn modal-btn-primary" onclick="validateAndSubmitAdd()">Add User</button>
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
                    <input type="text" id="edit-username" name="username" readonly style="background-color: #f8f9fa; color: #6c757d;">
                    <small style="color: #6c757d; font-style: italic;">Username cannot be changed</small>
                </div>
                <div class="modal-form-group">
                    <label for="edit-email">Email: <span style="color: red;">*</span></label>
                    <input type="email" id="edit-email" name="email" required>
                </div>
                <div class="modal-form-group">
                    <label for="edit-first-name">First Name: <span style="color: red;">*</span></label>
                    <input type="text" id="edit-first-name" name="first_name" required>
                </div>
                <div class="modal-form-group">
                    <label for="edit-last-name">Last Name: <span style="color: red;">*</span></label>
                    <input type="text" id="edit-last-name" name="last_name" required>
                </div>
                <div class="modal-form-group">
                    <label for="edit-country">Country: <span style="color: red;">*</span></label>
                    <input type="text" id="edit-country" name="country" required>
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
                    <button type="button" class="modal-btn modal-btn-primary" onclick="validateAndSubmitEdit()">Save Changes</button>
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

        // Close modal when clicking outside of it - DISABLED
        // window.onclick = function(event) {
        //     const addModal = document.getElementById('addModal');
        //     const editModal = document.getElementById('editModal');
        //     const deleteModal = document.getElementById('deleteModal');

        //     if (event.target == addModal) {
        //         closeAddModal();
        //     }
        //     if (event.target == editModal) {
        //         closeEditModal();
        //     }
        //     if (event.target == deleteModal) {
        //         closeDeleteModal();
        //     }
        // }

        // Close modal with Escape key - DISABLED
        // document.addEventListener('keydown', function(event) {
        //     if (event.key === 'Escape') {
        //         closeAddModal();
        //         closeEditModal();
        //         closeDeleteModal();
        //     }
        // });
    </script>
</body>
</html>