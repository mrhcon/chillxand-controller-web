<?php
header('Content-Type: application/json');
session_start();

// Check authentication
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'error' => 'Not authenticated']);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'Invalid request method']);
    exit();
}

$action = $_POST['action'] ?? '';
$device_ip = $_POST['device_ip'] ?? '';
$device_id = $_POST['device_id'] ?? '';

// Validate inputs
if (empty($device_ip)) {
    echo json_encode(['success' => false, 'error' => 'No device IP provided']);
    exit();
}

if (!filter_var($device_ip, FILTER_VALIDATE_IP)) {
    echo json_encode(['success' => false, 'error' => 'Invalid IP address']);
    exit();
}

// Determine the endpoint URL
if ($action === 'update_controller') {
    $url = "http://{$device_ip}:3001/update/controller";
} elseif ($action === 'update_pod') {
    $url = "http://{$device_ip}:3001/update/pod";
} else {
    echo json_encode(['success' => false, 'error' => 'Invalid action']);
    exit();
}

// Make the HTTP request to the device
$context = stream_context_create([
    'http' => [
        'method' => 'GET',
        'timeout' => 30,
        'header' => [
            'Accept: application/json',
            'User-Agent: ChillXand-Management-Console'
        ]
    ]
]);

// Call the device
$response = @file_get_contents($url, false, $context);

if ($response === false) {
    $error = error_get_last();
    echo json_encode([
        'success' => false, 
        'error' => "Failed to contact device at {$device_ip}:3001 - " . ($error['message'] ?? 'Connection failed')
    ]);
} else {
    // Forward the device's JSON response directly
    echo $response;
}
?>