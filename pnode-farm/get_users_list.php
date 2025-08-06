<?php
// CREATE NEW FILE: get_users_list.php
session_start();
require_once 'db_connect.php';

header('Content-Type: application/json');

// Check if user is logged in and is admin
if (!isset($_SESSION['user_id']) || !$_SESSION['admin']) {
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit();
}

try {
    // Get all users for the dropdown
    $stmt = $pdo->prepare("
        SELECT username, first_name, last_name, email 
        FROM users 
        ORDER BY first_name ASC, last_name ASC, username ASC
    ");
    $stmt->execute();
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo json_encode([
        'success' => true,
        'users' => $users
    ]);
    
} catch (PDOException $e) {
    error_log("Error getting users list: " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'error' => 'Database error'
    ]);
}
?>