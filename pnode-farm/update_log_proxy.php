<?php
header('Content-Type: text/plain');
session_start();

if (!isset($_SESSION['user_id'])) {
    http_response_code(403);
    echo 'Not authenticated';
    exit();
}

$device_ip = $_GET['device_ip'] ?? '';
$update_type = $_GET['update_type'] ?? '';

if (empty($device_ip) || empty($update_type)) {
    http_response_code(400);
    echo 'Missing parameters';
    exit();
}

if (!filter_var($device_ip, FILTER_VALIDATE_IP)) {
    http_response_code(400);
    echo 'Invalid IP address';
    exit();
}

if (!in_array($update_type, ['controller', 'pod'])) {
    http_response_code(400);
    echo 'Invalid update type';
    exit();
}

$url = "http://{$device_ip}:3001/update/{$update_type}/log";

$context = stream_context_create([
    'http' => [
        'method' => 'GET',
        'timeout' => 10,
        'header' => [
            'Accept: text/plain',
            'User-Agent: ChillXand-Management-Console'
        ]
    ]
]);

$response = @file_get_contents($url, false, $context);

if ($response === false) {
    http_response_code(500);
    echo 'Failed to fetch logs';
} else {
    echo $response;
}
?>