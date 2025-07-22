<?php
/**
 * manual_device_check.php - On-demand device status check (port 3001)
 */

session_start();
require_once 'db_connect.php';

header('Content-Type: application/json');
set_time_limit(10);

if (!isset($_SESSION['user_id']) || !isset($_POST['device_id'])) {
    echo json_encode(['error' => 'Invalid request']);
    exit();
}

$device_id = (int)$_POST['device_id'];

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
        echo json_encode(['error' => 'Device not found or access denied']);
        exit();
    }
    
    if (!filter_var($device['pnode_ip'], FILTER_VALIDATE_IP)) {
        echo json_encode(['error' => 'Invalid IP address']);
        exit();
    }
    
    // Get consecutive failures from last check
    $stmt = $pdo->prepare("
        SELECT consecutive_failures 
        FROM device_status_log 
        WHERE device_id = ? 
        ORDER BY check_time DESC 
        LIMIT 1
    ");
    $stmt->execute([$device_id]);
    $last_check = $stmt->fetch(PDO::FETCH_ASSOC);
    $last_consecutive_failures = $last_check['consecutive_failures'] ?? 0;
    
    // Perform status check on port 3001 (health endpoint port)
    $ip = $device['pnode_ip'];
    $start_time = microtime(true);
    $status = 'Unknown';
    $response_time = null;
    $error_message = null;
    $check_method = 'manual';
    
    // Health data variables
    $health_status = null;
    $atlas_registered = null;
    $pod_status = null;
    $xandminer_status = null;
    $xandminerd_status = null;
    $cpu_load_avg = null;
    $memory_percent = null;
    $memory_total_bytes = null;
    $memory_used_bytes = null;
    $server_ip = null;
    $server_hostname = null;
    $chillxand_version = null;
    $node_version = null;
    $health_json = null;
    
    // Try port 3001 first (where health endpoint lives)
    $connection = @fsockopen($ip, 3001, $errno, $errstr, 3);
    if ($connection) {
        fclose($connection);
        $status = 'Online';
        $response_time = microtime(true) - $start_time;
        $check_method = 'manual:fsockopen:3001';
        
        // Since port 3001 is open, try to fetch health data
        $health_start = microtime(true);
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => "http://$ip:3001/health",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'Manual-Device-Check/1.0'
        ]);
        
        $health_response = curl_exec($ch);
        $health_http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $health_error = curl_error($ch);
        curl_close($ch);
        
        if ($health_response !== false && $health_http_code === 200 && empty($health_error)) {
            $health_data = json_decode($health_response, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($health_data)) {
                $health_json = $health_response;
                $check_method .= '+health';
                
                // Parse health data
                $health_status = $health_data['status'] ?? null;
                $node_version = $health_data['version'] ?? null;
                $chillxand_version = $health_data['chillxand_controller_version'] ?? null;
                
                if (isset($health_data['server_info'])) {
                    $server_ip = $health_data['server_info']['ip'] ?? null;
                    $server_hostname = $health_data['server_info']['hostname'] ?? null;
                }
                
                // Parse checks array
                if (isset($health_data['checks']) && is_array($health_data['checks'])) {
                    foreach ($health_data['checks'] as $check_name => $check_data) {
                        switch ($check_name) {
                            case 'system:cpu':
                                if (isset($check_data['observedValue'])) {
                                    $cpu_load_avg = (float)$check_data['observedValue'];
                                }
                                break;
                                
                            case 'system:memory':
                                if (isset($check_data['observedValue'])) {
                                    $memory_percent = (float)$check_data['observedValue'];
                                }
                                if (isset($check_data['memory_total_bytes'])) {
                                    $memory_total_bytes = (int)$check_data['memory_total_bytes'];
                                }
                                if (isset($check_data['memory_used_bytes'])) {
                                    $memory_used_bytes = (int)$check_data['memory_used_bytes'];
                                }
                                break;
                                
                            case 'atlas:registration':
                                $atlas_registered = isset($check_data['registered']) ? (bool)$check_data['registered'] : false;
                                break;
                                
                            case 'service:pod':
                                if (isset($check_data['observedValue'])) {
                                    $pod_status = strtolower($check_data['observedValue']);
                                }
                                break;
                                
                            case 'service:xandminer':
                                if (isset($check_data['observedValue'])) {
                                    $xandminer_status = strtolower($check_data['observedValue']);
                                }
                                break;
                                
                            case 'service:xandminerd':
                                if (isset($check_data['observedValue'])) {
                                    $xandminerd_status = strtolower($check_data['observedValue']);
                                }
                                break;
                        }
                    }
                }
            }
        }
    } else {
        // Try port 80 as fallback
        $connection = @fsockopen($ip, 80, $errno2, $errstr2, 2);
        if ($connection) {
            fclose($connection);
            $status = 'Online';
            $response_time = microtime(true) - $start_time;
            $check_method = 'manual:fsockopen:80';
        } else {
            $status = 'Offline';
            $response_time = microtime(true) - $start_time;
            $error_message = "Port 3001/80 unreachable: 3001($errstr), 80($errstr2)";
            $check_method = 'manual:fsockopen:failed';
        }
    }
    
    // Calculate consecutive failures
    $consecutive_failures = 0;
    if ($status === 'Offline' || $status === 'Error') {
        $consecutive_failures = $last_consecutive_failures + 1;
    }
    
    // Insert new status log entry with full health data
    $stmt = $pdo->prepare("
        INSERT INTO device_status_log (
            device_id, status, check_time, response_time, check_method, 
            error_message, consecutive_failures,
            health_status, atlas_registered, pod_status, xandminer_status, xandminerd_status,
            cpu_load_avg, memory_percent, memory_total_bytes, memory_used_bytes,
            server_ip, server_hostname, chillxand_version, node_version, health_json
        ) VALUES (?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ");
    
    $stmt->execute([
        $device_id,
        $status,
        $response_time,
        $check_method,
        $error_message,
        $consecutive_failures,
        $health_status,
        $atlas_registered,
        $pod_status,
        $xandminer_status,
        $xandminerd_status,
        $cpu_load_avg,
        $memory_percent,
        $memory_total_bytes,
        $memory_used_bytes,
        $server_ip,
        $server_hostname,
        $chillxand_version,
        $node_version,
        $health_json
    ]);
    
    // Log the manual check
    require_once 'functions.php';
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 
                   'manual_device_check', 
                   "Device: {$device['pnode_name']}, IP: $ip, Status: $status, Response: " . 
                   round($response_time * 1000, 1) . "ms, Method: $check_method");
    
    echo json_encode([
        'status' => $status,
        'response_time' => round($response_time * 1000, 1),
        'device_name' => $device['pnode_name'],
        'timestamp' => date('Y-m-d H:i:s'),
        'consecutive_failures' => $consecutive_failures,
        'check_method' => $check_method,
        'health_status' => $health_status,
        'atlas_registered' => $atlas_registered,
        'pod_status' => $pod_status,
        'xandminer_status' => $xandminer_status,
        'xandminerd_status' => $xandminerd_status,
        'cpu_load_avg' => $cpu_load_avg,
        'memory_percent' => $memory_percent,
        'server_hostname' => $server_hostname,
        'chillxand_version' => $chillxand_version
    ]);
    
} catch (Exception $e) {
    error_log("Manual device check error: " . $e->getMessage());
    echo json_encode(['error' => 'Check failed: ' . $e->getMessage()]);
}
?>