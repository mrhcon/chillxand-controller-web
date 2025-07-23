<?php
/**
 * device_update.php - Handle controller and pod update requests
 */

session_start();
require_once 'db_connect.php';
require_once 'functions.php';

header('Content-Type: application/json');
set_time_limit(30);

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'error' => 'User not logged in']);
    exit();
}

// Check required POST parameters
if (!isset($_POST['action']) || !isset($_POST['device_id']) || !isset($_POST['device_ip'])) {
    echo json_encode(['success' => false, 'error' => 'Missing required parameters']);
    exit();
}

$action = $_POST['action'];
$device_id = (int)$_POST['device_id'];
$device_ip = trim($_POST['device_ip']);

// Validate action
if (!in_array($action, ['update_controller', 'update_pod'])) {
    echo json_encode(['success' => false, 'error' => 'Invalid action']);
    exit();
}

// Validate IP address
if (!filter_var($device_ip, FILTER_VALIDATE_IP)) {
    echo json_encode(['success' => false, 'error' => 'Invalid IP address']);
    exit();
}

try {
    // Verify user has access to this device
    $stmt = $pdo->prepare("
        SELECT d.pnode_name, d.pnode_ip, d.username 
        FROM devices d 
        WHERE d.id = ? AND (d.username = ? OR ? = 1)
    ");
    $stmt->execute([$device_id, $_SESSION['username'], $_SESSION['admin'] ?? 0]);
    $device = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$device) {
        echo json_encode(['success' => false, 'error' => 'Device not found or access denied']);
        exit();
    }
    
    // Verify IP matches
    if ($device['pnode_ip'] !== $device_ip) {
        echo json_encode(['success' => false, 'error' => 'IP address mismatch']);
        exit();
    }
    
    // Determine the endpoint URL based on action
    $endpoint = '';
    $action_name = '';
    switch ($action) {
        case 'update_controller':
            $endpoint = "http://$device_ip:3001/update/controller";
            $action_name = 'Controller Update';
            break;
        case 'update_pod':
            $endpoint = "http://$device_ip:3001/update/pod";
            $action_name = 'Pod Update';
            break;
    }
    
    // Log the update attempt
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 
                   "device_update_attempt", 
                   "Action: $action_name, Device: {$device['pnode_name']}, IP: $device_ip");
    
    // Make the update request
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $endpoint,
        CURLOPT_CUSTOMREQUEST => 'GET',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_FAILONERROR => false,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_USERAGENT => 'ChillXand-Management-Console/1.0',
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'Accept: application/json'
        ]
    ]);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);
    $response_time = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
    curl_close($ch);
    
    // Process the response
    if ($response === false || !empty($curl_error)) {
        $error_msg = "Connection failed: " . ($curl_error ?: 'Unknown network error');
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 
                       "device_update_failed", 
                       "Action: $action_name, Device: {$device['pnode_name']}, Error: $error_msg");
        
        echo json_encode([
            'success' => false, 
            'error' => $error_msg,
            'details' => [
                'endpoint' => $endpoint,
                'response_time' => $response_time
            ]
        ]);
        exit();
    }
    
    // Check HTTP status code
    if ($http_code < 200 || $http_code >= 300) {
        $error_msg = "HTTP Error $http_code";
        $response_preview = substr($response, 0, 200);
        
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 
                       "device_update_failed", 
                       "Action: $action_name, Device: {$device['pnode_name']}, HTTP: $http_code, Response: $response_preview");
        
        echo json_encode([
            'success' => false, 
            'error' => $error_msg,
            'details' => [
                'http_code' => $http_code,
                'endpoint' => $endpoint,
                'response_preview' => $response_preview,
                'response_time' => $response_time
            ]
        ]);
        exit();
    }
    
    // Try to parse JSON response
    $response_data = json_decode($response, true);
    $json_error = json_last_error();
    
    if ($json_error !== JSON_ERROR_NONE) {
        // Non-JSON response, treat as success if HTTP was 200
        $response_preview = substr($response, 0, 200);
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 
                       "device_update_success", 
                       "Action: $action_name, Device: {$device['pnode_name']}, HTTP: $http_code, Response: $response_preview");
        
        echo json_encode([
            'success' => true,
            'message' => "$action_name initiated successfully",
            'details' => [
                'http_code' => $http_code,
                'endpoint' => $endpoint,
                'response_preview' => $response_preview,
                'response_time' => round($response_time, 2) . 's'
            ]
        ]);
        exit();
    }
    
    // JSON response received
    $success_message = "$action_name initiated successfully";
    if (isset($response_data['message'])) {
        $success_message = $response_data['message'];
    } elseif (isset($response_data['status'])) {
        $success_message = $response_data['status'];
    }
    
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 
                   "device_update_success", 
                   "Action: $action_name, Device: {$device['pnode_name']}, Response: " . json_encode($response_data));
    
    echo json_encode([
        'success' => true,
        'message' => $success_message,
        'details' => [
            'http_code' => $http_code,
            'endpoint' => $endpoint,
            'response_data' => $response_data,
            'response_time' => round($response_time, 2) . 's'
        ]
    ]);
    
} catch (PDOException $e) {
    error_log("Database error in device_update.php: " . $e->getMessage());
    echo json_encode([
        'success' => false, 
        'error' => 'Database error occurred'
    ]);
} catch (Exception $e) {
    error_log("General error in device_update.php: " . $e->getMessage());
    echo json_encode([
        'success' => false, 
        'error' => 'An unexpected error occurred: ' . $e->getMessage()
    ]);
}
?>