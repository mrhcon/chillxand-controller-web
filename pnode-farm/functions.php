<?php
// functions.php - Updated for health endpoint and single table approach
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once 'db_connect.php';

function logInteraction($pdo, $user_id, $username, $action, $details = null) {
    try {
        // Truncate details to avoid exceeding TEXT column limit (65,535 bytes)
        $details = substr($details ?? '', 0, 65535);
        $stmt = $pdo->prepare("INSERT INTO user_interactions (user_id, username, action, details) VALUES (?, ?, ?, ?)");
        $stmt->execute([$user_id, $username, $action, $details]);
    } catch (PDOException $e) {
        error_log("Failed to log interaction: " . $e->getMessage());
    }
}

/**
 * Get latest device status from log (handles missing data gracefully)
 */
function getLatestDeviceStatus($pdo, $device_id) {
    try {
        $stmt = $pdo->prepare("
            SELECT dsl.status, dsl.check_time, dsl.response_time, dsl.consecutive_failures,
                   dsl.health_status, dsl.atlas_registered, dsl.pod_status, 
                   dsl.xandminer_status, dsl.xandminerd_status, dsl.cpu_load_avg, 
                   dsl.memory_percent, dsl.memory_total_bytes, dsl.memory_used_bytes,
                   dsl.server_ip, dsl.server_hostname, dsl.chillxand_version, 
                   dsl.node_version, dsl.error_message, dsl.check_method,
                   d.pnode_name, d.pnode_ip,
                   TIMESTAMPDIFF(MINUTE, dsl.check_time, NOW()) as age_minutes
            FROM device_status_log dsl
            JOIN devices d ON dsl.device_id = d.id
            WHERE dsl.device_id = ?
            ORDER BY dsl.check_time DESC
            LIMIT 1
        ");
        $stmt->execute([$device_id]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$result) {
            // No status record exists - return default values
            return [
                'status' => 'Not Initialized',
                'check_time' => null,
                'response_time' => null,
                'age_minutes' => null,
                'is_stale' => true,
                'health_status' => null,
                'atlas_registered' => null,
                'pod_status' => null,
                'xandminer_status' => null,
                'xandminerd_status' => null,
                'cpu_load_avg' => null,
                'memory_percent' => null,
                'memory_total_bytes' => null,
                'memory_used_bytes' => null,
                'server_ip' => null,
                'server_hostname' => null,
                'chillxand_version' => null,
                'node_version' => null,
                'error_message' => 'Device has not been checked yet',
                'consecutive_failures' => 0,
                'check_method' => null
            ];
        }
        
        // Determine if status is stale (older than 15 minutes)
        $is_stale = ($result['age_minutes'] > 15);
        
        return [
            'status' => $result['status'],
            'check_time' => $result['check_time'],
            'response_time' => $result['response_time'],
            'age_minutes' => $result['age_minutes'],
            'is_stale' => $is_stale,
            'consecutive_failures' => $result['consecutive_failures'],
            'health_status' => $result['health_status'],
            'atlas_registered' => $result['atlas_registered'],
            'pod_status' => $result['pod_status'],
            'xandminer_status' => $result['xandminer_status'],
            'xandminerd_status' => $result['xandminerd_status'],
            'cpu_load_avg' => $result['cpu_load_avg'],
            'memory_percent' => $result['memory_percent'],
            'memory_total_bytes' => $result['memory_total_bytes'],
            'memory_used_bytes' => $result['memory_used_bytes'],
            'server_ip' => $result['server_ip'],
            'server_hostname' => $result['server_hostname'],
            'chillxand_version' => $result['chillxand_version'],
            'node_version' => $result['node_version'],
            'error_message' => $result['error_message'],
            'check_method' => $result['check_method']
        ];
        
    } catch (PDOException $e) {
        error_log("Error getting latest device status: " . $e->getMessage());
        return [
            'status' => 'Error',
            'check_time' => null,
            'response_time' => null,
            'age_minutes' => null,
            'is_stale' => true,
            'error_message' => 'Database error',
            'consecutive_failures' => 0
        ];
    }
}

/**
 * Get latest statuses for multiple devices efficiently
 */
function getLatestDeviceStatuses($pdo, $device_ids) {
    if (empty($device_ids)) {
        return [];
    }
    
    try {
        $placeholders = str_repeat('?,', count($device_ids) - 1) . '?';
        
        // Get latest status for each device using a window function
        $stmt = $pdo->prepare("
            SELECT device_id, status, check_time, response_time, consecutive_failures,
                   health_status, atlas_registered, pod_status, xandminer_status, xandminerd_status,
                   cpu_load_avg, memory_percent, memory_total_bytes, memory_used_bytes,
                   server_ip, server_hostname, chillxand_version, node_version,
                   error_message, check_method,
                   TIMESTAMPDIFF(MINUTE, check_time, NOW()) as age_minutes
            FROM (
                SELECT device_id, status, check_time, response_time, consecutive_failures,
                       health_status, atlas_registered, pod_status, xandminer_status, xandminerd_status,
                       cpu_load_avg, memory_percent, memory_total_bytes, memory_used_bytes,
                       server_ip, server_hostname, chillxand_version, node_version,
                       error_message, check_method,
                       ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY check_time DESC) as rn
                FROM device_status_log
                WHERE device_id IN ($placeholders)
            ) ranked
            WHERE rn = 1
        ");
        $stmt->execute($device_ids);
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Index by device_id and calculate staleness
        $statuses = [];
        foreach ($results as $result) {
            $is_stale = ($result['age_minutes'] > 15);
            
            $statuses[$result['device_id']] = [
                'status' => $result['status'],
                'check_time' => $result['check_time'],
                'response_time' => $result['response_time'],
                'age_minutes' => $result['age_minutes'],
                'is_stale' => $is_stale,
                'consecutive_failures' => $result['consecutive_failures'],
                'health_status' => $result['health_status'],
                'atlas_registered' => $result['atlas_registered'],
                'pod_status' => $result['pod_status'],
                'xandminer_status' => $result['xandminer_status'],
                'xandminerd_status' => $result['xandminerd_status'],
                'cpu_load_avg' => $result['cpu_load_avg'],
                'memory_percent' => $result['memory_percent'],
                'memory_total_bytes' => $result['memory_total_bytes'],
                'memory_used_bytes' => $result['memory_used_bytes'],
                'server_ip' => $result['server_ip'],
                'server_hostname' => $result['server_hostname'],
                'chillxand_version' => $result['chillxand_version'],
                'node_version' => $result['node_version'],
                'error_message' => $result['error_message'],
                'check_method' => $result['check_method']
            ];
        }
        
        // Fill in missing devices with default status (no seeding required)
        foreach ($device_ids as $device_id) {
            if (!isset($statuses[$device_id])) {
                $statuses[$device_id] = [
                    'status' => 'Not Initialized',
                    'check_time' => null,
                    'response_time' => null,
                    'age_minutes' => null,
                    'is_stale' => true,
                    'error_message' => 'Device has not been checked yet',
                    'consecutive_failures' => 0,
                    'health_status' => null,
                    'atlas_registered' => null,
                    'pod_status' => null,
                    'xandminer_status' => null,
                    'xandminerd_status' => null,
                    'cpu_load_avg' => null,
                    'memory_percent' => null,
                    'memory_total_bytes' => null,
                    'memory_used_bytes' => null,
                    'server_ip' => null,
                    'server_hostname' => null,
                    'chillxand_version' => null,
                    'node_version' => null
                ];
            }
        }
        
        return $statuses;
        
    } catch (PDOException $e) {
        error_log("Error getting latest device statuses: " . $e->getMessage());
        return [];
    }
}

/**
 * Parse cached device health data from the single table
 */
function parseCachedDeviceHealth($cached_status) {
    $result = [
        'error' => null,
        'health_status' => $cached_status['health_status'],
        'atlas_registered' => $cached_status['atlas_registered'],
        'pod_status' => $cached_status['pod_status'],
        'xandminer_status' => $cached_status['xandminer_status'],
        'xandminerd_status' => $cached_status['xandminerd_status'],
        'cpu_load_avg' => $cached_status['cpu_load_avg'],
        'memory_percent' => $cached_status['memory_percent'],
        'memory_total_bytes' => $cached_status['memory_total_bytes'],
        'memory_used_bytes' => $cached_status['memory_used_bytes'],
        'server_ip' => $cached_status['server_ip'],
        'server_hostname' => $cached_status['server_hostname'],
        'chillxand_version' => $cached_status['chillxand_version'],
        'node_version' => $cached_status['node_version'],
        'last_update' => $cached_status['check_time']
    ];

    // Check if health data is recent
    if ($cached_status['check_time']) {
        $update_time = new DateTime($cached_status['check_time']);
        $now = new DateTime();
        $age_hours = ($now->getTimestamp() - $update_time->getTimestamp()) / 3600;
        
        if ($age_hours > 2) {
            $result['error'] = 'Health data is stale (last updated ' . 
                               $cached_status['check_time'] . ')';
        }
    } else {
        $result['error'] = 'Device has not been checked yet';
    }

    return $result;
}

/**
 * DEPRECATED: Keep old functions for backwards compatibility
 */
function pingDevice($ip, $pdo, $user_id, $username, $port = 80, $timeout = 2) {
    error_log("DEPRECATED: pingDevice called from UI - should use getLatestDeviceStatus instead");
    
    $start_time = microtime(true);
    $details = "Device IP: $ip, Port: $port, Timeout: {$timeout}s";

    $connection = @fsockopen($ip, $port, $errno, $errstr, $timeout);
    $fsock_time = microtime(true) - $start_time;
    $details .= ", fsockopen Time: " . number_format($fsock_time, 3) . "s";

    if ($connection) {
        fclose($connection);
        $status = 'Online';
        $details .= ", Status: $status, Method: fsockopen";
        $action = 'device_status_check_success';
    } else {
        $details .= ", fsockopen Error: " . ($errstr ?: 'Unknown') . " ($errno)";
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
    return bin2hex(random_bytes(16));
}

function sendResetCodeEmail($email, $username, $reset_code) {
    $subject = "Password Reset Code";
    $message = "Dear $username,\n\nYour password reset code is: $reset_code\n\nThis code is valid for 1 hour. Please use it on the reset password page.\n\nBest regards,\nNetwork Management Console";
    $headers = "From: no-reply@networkconsole.example.com\r\n";
    
    error_log("Email to $email: Subject: $subject, Message: $message");
    return true;
}

function fetchDeviceSummary($ip) {
    error_log("DEPRECATED: fetchDeviceSummary called from UI - health data should come from device_status_log");
    
    $url = "http://$ip:3001/summary";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
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

function parseDeviceSummary($json_data, $ip) {
    error_log("DEPRECATED: parseDeviceSummary called - should use parseCachedDeviceHealth");
    
    $result = [
        'error' => null,
        'uptime' => null,
        'cpu_usage' => null,
        'memory_usage' => null,
        'disk_space' => null,
        'network_traffic' => null,
        'raw_data' => []
    ];

    if (isset($json_data['error'])) {
        $result['error'] = $json_data['error'];
        return $result;
    }

    if (!is_array($json_data)) {
        $result['error'] = 'Invalid JSON format.';
        return $result;
    }

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
                $result['raw_data'][$key] = $value;
        }
    }

    return $result;
}
?>