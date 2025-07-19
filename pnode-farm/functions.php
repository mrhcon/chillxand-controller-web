<?php
// functions.php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once 'db_connect.php';

function logInteraction($pdo, $user_id, $username, $action, $details = null) {
    try {
        // Truncate details to avoid exceeding TEXT column limit (65,535 bytes)
        $details = substr($details, 0, 65535);
        $stmt = $pdo->prepare("INSERT INTO user_interactions (user_id, username, action, details) VALUES (?, ?, ?, ?)");
        $stmt->execute([$user_id, $username, $action, $details]);
    } catch (PDOException $e) {
        error_log("Failed to log interaction: " . $e->getMessage());
    }
}


function pingDevice($ip, $pdo, $user_id, $username, $port = 80, $timeout = 2) {
    $start_time = microtime(true);
    $details = "Device IP: $ip, Port: $port, Timeout: {$timeout}s";

    // Step 1: Try fsockopen on port 80
    $fsock_start = microtime(true);
    $connection = @fsockopen($ip, $port, $errno, $errstr, $timeout);
    $fsock_time = microtime(true) - $fsock_start;
    $details .= ", fsockopen Time: " . number_format($fsock_time, 3) . "s";

    if ($connection) {
        fclose($connection);
        $status = 'Online';
        $details .= ", Status: $status, Method: fsockopen";
        $action = 'device_status_check_success';
    } else {
        $details .= ", fsockopen Error: " . ($errstr ?: 'Unknown') . " ($errno)";
        // Step 2: Fallback to ICMP ping if fsockopen fails
        $ping_start = microtime(true);
        $ping_command = strncasecmp(PHP_OS, 'WIN', 3) == 0 ? "ping -n 1 $ip" : "ping -c 1 -W $timeout $ip";
        exec($ping_command, $output, $return_var);
        $ping_time = microtime(true) - $ping_start;
        $ping_success = $return_var === 0;
        $details .= ", Ping Time: " . number_format($ping_time, 3) . "s";

        if ($ping_success) {
            $status = 'Online';
            $details .= ", Status: $status, Method: ping";
            $action = 'device_status_check_success';
        } else {
            $status = 'Offline';
            $details .= ", Status: $status, Method: fsockopen/ping failed";
            $action = 'device_status_check_failed';
        }
    }

    logInteraction($pdo, $user_id, $username, $action, $details);
    return ['status' => $status];
}

function generateResetCode() {
    return bin2hex(random_bytes(16)); // Generates a 32-character random code
}


function sendResetCodeEmail($email, $username, $reset_code) {
    $subject = "Password Reset Code";
    $message = "Dear $username,\n\nYour password reset code is: $reset_code\n\nThis code is valid for 1 hour. Please use it on the reset password page.\n\nBest regards,\nNetwork Management Console";
    $headers = "From: no-reply@networkconsole.example.com\r\n";
    
    // For testing, log email instead of sending (replace with mail() in production)
    error_log("Email to $email: Subject: $subject, Message: $message");
    return true; // Simulate successful email sending
    // Uncomment for production:
    // return mail($email, $subject, $message, $headers);
}


function fetchDeviceSummary($ip) {
    $url = "http://$ip:3001/summary";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5); // 5-second timeout
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($http_code !== 200 || $error) {
        error_log("Failed to fetch summary for IP $ip: HTTP $http_code, Error: $error");
        return ['error' => 'Failed to fetch device summary.'];
    }

    $data = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log("JSON decode error for IP $ip: " . json_last_error_msg());
        return ['error' => 'Invalid JSON response from device.'];
    }

    return $data;
}


// New function to parse JSON summary into PHP variables
function parseDeviceSummary($json_data, $ip) {
    $result = [
        'error' => null,
        'uptime' => null,
        'cpu_usage' => null,
        'memory_usage' => null,
        'disk_space' => null,
        'network_traffic' => null,
        'raw_data' => [] // Store unparsed fields
    ];

    // Check for fetch errors
    if (isset($json_data['error'])) {
        $result['error'] = $json_data['error'];
        error_log("Parse error for IP $ip: {$result['error']}");
        return $result;
    }

    // Parse JSON data
    if (!is_array($json_data)) {
        $result['error'] = 'Invalid JSON format.';
        error_log("Parse error for IP $ip: Invalid JSON format.");
        return $result;
    }

    // Map JSON keys to variables
    foreach ($json_data as $key => $value) {
        $normalized_key = strtolower(trim($key));
        switch ($normalized_key) {
            case 'uptime':
                $result['uptime'] = is_scalar($value) ? $value : json_encode($value);
                break;
            case 'cpu_usage':
                $result['cpu_usage'] = is_scalar($value) ? $value : json_encode($value);
                break;
            case 'memory_usage':
                $result['memory_usage'] = is_scalar($value) ? $value : json_encode($value);
                break;
            case 'disk_space':
                $result['disk_space'] = is_scalar($value) ? $value : json_encode($value);
                break;
            case 'network_traffic':
                $result['network_traffic'] = is_scalar($value) ? $value : json_encode($value);
                break;
            default:
                $result['raw_data'][$key] = $value; // Store unmapped fields
        }
    }

    // Log parsed data for debugging
    error_log("Parsed summary for IP $ip: " . json_encode([
        'uptime' => $result['uptime'],
        'cpu_usage' => $result['cpu_usage'],
        'memory_usage' => $result['memory_usage'],
        'disk_space' => $result['disk_space'],
        'network_traffic' => $result['network_traffic'],
        'raw_data' => $result['raw_data']
    ]));

    return $result;
}

?>