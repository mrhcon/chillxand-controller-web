<?php
session_start();
require_once 'db_connect.php';
require_once 'functions.php';

header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'error' => 'Not logged in']);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $action = $_POST['action'] ?? '';
    $pnode_name = trim($_POST['pnode_name'] ?? '');
    $pnode_ip = trim($_POST['pnode_ip'] ?? '');
    $device_id = $_POST['device_id'] ?? null;

    // Validate fields
    if (empty($pnode_name) || empty($pnode_ip)) {
        echo json_encode(['success' => false, 'errors' => [
            'name' => empty($pnode_name) ? 'Node name is required.' : '',
            'ip' => empty($pnode_ip) ? 'IP address is required.' : ''
        ]]);
        exit();
    }

    if (strlen($pnode_name) > 100) {
        echo json_encode(['success' => false, 'errors' => [
            'name' => 'Node name must be 100 characters or less.'
        ]]);
        exit();
    }

    if (!filter_var($pnode_ip, FILTER_VALIDATE_IP)) {
        echo json_encode(['success' => false, 'errors' => [
            'ip' => 'Invalid IP address.'
        ]]);
        exit();
    }

    try {
        // Check for duplicate name system-wide
        if ($action === 'edit' && $device_id) {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE pnode_name = :pnode_name AND id != :device_id");
            $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
        } else {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE pnode_name = :pnode_name");
        }
        $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
        $stmt->execute();
        
        if ($stmt->fetchColumn() > 0) {
            echo json_encode(['success' => false, 'errors' => [
                'name' => 'Device name already registered in the system.'
            ]]);
            exit();
        }

        // Check for duplicate IP address system-wide
        if ($action === 'edit' && $device_id) {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE pnode_ip = :pnode_ip AND id != :device_id");
            $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
        } else {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE pnode_ip = :pnode_ip");
        }
        $stmt->bindValue(':pnode_ip', $pnode_ip, PDO::PARAM_STR);
        $stmt->execute();
        
        if ($stmt->fetchColumn() > 0) {
            echo json_encode(['success' => false, 'errors' => [
                'ip' => 'IP address already registered in the system.'
            ]]);
            exit();
        }

        echo json_encode(['success' => true]);

    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'error' => 'Database error occurred.']);
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_validation_failed', $e->getMessage());
    }
}
?>