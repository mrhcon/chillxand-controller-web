<?php
// manual_device_check.php - Clean version with proper column mapping
session_start();
header('Content-Type: application/json');

require_once 'db_connect.php';
require_once 'functions.php';

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['error' => 'Not authenticated']);
    exit();
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['device_id'])) {
    echo json_encode(['error' => 'Invalid request']);
    exit();
}

$device_id = (int)$_POST['device_id'];

try {
    // Get device details
    $stmt = $pdo->prepare("
        SELECT d.id, d.pnode_name, d.pnode_ip 
        FROM devices d 
        WHERE d.id = :device_id AND (d.username = :username OR :admin = 1)
    ");
    $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
    $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
    $stmt->bindValue(':admin', $_SESSION['admin'] ?? 0, PDO::PARAM_INT);
    $stmt->execute();
    
    $device = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$device) {
        echo json_encode(['error' => 'Device not found or access denied']);
        exit();
    }
    
    // Initialize all variables
    $status = 'Online';
    $health_status = null;
    $chillxand_version = null;
    $atlas_registered = false;
    $pod_status = null;
    $xandminer_status = null;
    $xandminerd_status = null;
    $cpu_load_avg = null;
    $memory_percent = null;
    $memory_total_bytes = null;
    $memory_used_bytes = null;
    $server_ip = null;
    $server_hostname = null;
    $pod_version = null;
    $xandminer_version = null;
    $xandminerd_version = null;
    
    // Test connectivity
    $ip = $device['pnode_ip'];
    $port = 3001;
    
    // Test if port is open
    $connection = @fsockopen($ip, $port, $errno, $errstr, 5);
    if (!$connection) {
        // Port is closed - device is offline
        $stmt = $pdo->prepare("
            INSERT INTO device_status_log (
                device_id, status, check_time, response_time, check_method, error_message, 
                health_status, atlas_registered, pod_status, xandminer_status, 
                xandminerd_status, cpu_load_avg, memory_percent, memory_total_bytes,
                memory_used_bytes, server_ip, server_hostname, chillxand_version,
                pod_version, xandminer_version, xandminerd_version, health_json,
                consecutive_failures
            ) VALUES (
                :device_id, :status, NOW(), :response_time, :check_method, :error_message,
                :health_status, :atlas_registered, :pod_status, :xandminer_status,
                :xandminerd_status, :cpu_load_avg, :memory_percent, :memory_total_bytes,
                :memory_used_bytes, :server_ip, :server_hostname, :chillxand_version,
                :pod_version, :xandminer_version, :xandminerd_version, :health_json,
                :consecutive_failures
            )
        ");
        
        $stmt->execute([
            ':device_id' => $device_id,
            ':status' => 'Offline',
            ':response_time' => null,
            ':check_method' => 'manual',
            ':error_message' => "Connection failed: {$errstr} ({$errno})",
            ':health_status' => null,
            ':atlas_registered' => false,
            ':pod_status' => null,
            ':xandminer_status' => null,
            ':xandminerd_status' => null,
            ':cpu_load_avg' => null,
            ':memory_percent' => null,
            ':memory_total_bytes' => null,
            ':memory_used_bytes' => null,
            ':server_ip' => $ip,
            ':server_hostname' => null,
            ':chillxand_version' => null,
            ':pod_version' => null,
            ':xandminer_version' => null,
            ':xandminerd_version' => null,
            ':health_json' => null,
            ':consecutive_failures' => 0
        ]);
        
        echo json_encode([
            'success' => true,
            'status' => 'Offline',
            'response_time' => 0,
            'consecutive_failures' => 0,
            'timestamp' => date('M j, H:i')
        ]);
        exit();
    }
    
    fclose($connection);
    
    // Get health data
    $url = "http://{$ip}:{$port}/health";
    $start_time = microtime(true);
    
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 15,
            'header' => [
                'Accept: application/json',
                'User-Agent: ChillXand-Management-Console'
            ]
        ]
    ]);
    
    $response = @file_get_contents($url, false, $context);
    $response_time = microtime(true) - $start_time;
    
    if ($response === false) {
        // HTTP request failed
        $stmt = $pdo->prepare("
            INSERT INTO device_status_log (
                device_id, status, check_time, response_time, check_method, error_message, 
                health_status, atlas_registered, pod_status, xandminer_status, 
                xandminerd_status, cpu_load_avg, memory_percent, memory_total_bytes,
                memory_used_bytes, server_ip, server_hostname, chillxand_version,
                pod_version, xandminer_version, xandminerd_version, health_json,
                consecutive_failures
            ) VALUES (
                :device_id, :status, NOW(), :response_time, :check_method, :error_message,
                :health_status, :atlas_registered, :pod_status, :xandminer_status,
                :xandminerd_status, :cpu_load_avg, :memory_percent, :memory_total_bytes,
                :memory_used_bytes, :server_ip, :server_hostname, :chillxand_version,
                :pod_version, :xandminer_version, :xandminerd_version, :health_json,
                :consecutive_failures
            )
        ");
        
        $stmt->execute([
            ':device_id' => $device_id,
            ':status' => 'Error',
            ':response_time' => $response_time,
            ':check_method' => 'manual',
            ':error_message' => 'HTTP request failed',
            ':health_status' => null,
            ':atlas_registered' => false,
            ':pod_status' => null,
            ':xandminer_status' => null,
            ':xandminerd_status' => null,
            ':cpu_load_avg' => null,
            ':memory_percent' => null,
            ':memory_total_bytes' => null,
            ':memory_used_bytes' => null,
            ':server_ip' => $ip,
            ':server_hostname' => null,
            ':chillxand_version' => null,
            ':pod_version' => null,
            ':xandminer_version' => null,
            ':xandminerd_version' => null,
            ':health_json' => null,
            ':consecutive_failures' => 0
        ]);
        
        echo json_encode([
            'success' => true,
            'status' => 'Error',
            'response_time' => round($response_time * 1000, 1),
            'consecutive_failures' => 0,
            'timestamp' => date('M j, H:i')
        ]);
        exit();
    }
    
    // Parse JSON response
    $health_data = json_decode($response, true);
    if ($health_data === null) {
        $stmt = $pdo->prepare("
            INSERT INTO device_status_log (
                device_id, status, check_time, response_time, check_method, error_message, 
                health_status, atlas_registered, pod_status, xandminer_status, 
                xandminerd_status, cpu_load_avg, memory_percent, memory_total_bytes,
                memory_used_bytes, server_ip, server_hostname, chillxand_version,
                pod_version, xandminer_version, xandminerd_version, health_json,
                consecutive_failures
            ) VALUES (
                :device_id, :status, NOW(), :response_time, :check_method, :error_message,
                :health_status, :atlas_registered, :pod_status, :xandminer_status,
                :xandminerd_status, :cpu_load_avg, :memory_percent, :memory_total_bytes,
                :memory_used_bytes, :server_ip, :server_hostname, :chillxand_version,
                :pod_version, :xandminer_version, :xandminerd_version, :health_json,
                :consecutive_failures
            )
        ");
        
        $stmt->execute([
            ':device_id' => $device_id,
            ':status' => 'Error',
            ':response_time' => $response_time,
            ':check_method' => 'manual',
            ':error_message' => 'Invalid JSON response',
            ':health_status' => null,
            ':atlas_registered' => false,
            ':pod_status' => null,
            ':xandminer_status' => null,
            ':xandminerd_status' => null,
            ':cpu_load_avg' => null,
            ':memory_percent' => null,
            ':memory_total_bytes' => null,
            ':memory_used_bytes' => null,
            ':server_ip' => $ip,
            ':server_hostname' => null,
            ':chillxand_version' => null,
            ':pod_version' => null,
            ':xandminer_version' => null,
            ':xandminerd_version' => null,
            ':health_json' => null,
            ':consecutive_failures' => 0
        ]);
        
        echo json_encode([
            'success' => true,
            'status' => 'Error',
            'response_time' => round($response_time * 1000, 1),
            'consecutive_failures' => 0,
            'timestamp' => date('M j, H:i')
        ]);
        exit();
    }
    
    // Extract basic health status
    $health_status = $health_data['status'] ?? null;
    
    // Extract ChillXand version
    $chillxand_version = $health_data['chillxand_controller_version'] ?? null;
    if (!$chillxand_version && isset($health_data['versions']['data']['chillxand_controller'])) {
        $chillxand_version = $health_data['versions']['data']['chillxand_controller'];
    }
    
    // Extract versions
    if (isset($health_data['versions']['data'])) {
        $pod_version = $health_data['versions']['data']['pod'] ?? null;
        $xandminer_version = $health_data['versions']['data']['xandminer'] ?? null;
        $xandminerd_version = $health_data['versions']['data']['xandminerd'] ?? null;
    }
    
    // Extract server info
    if (isset($health_data['checks']['connectivity']['server_info'])) {
        $server_ip = $health_data['checks']['connectivity']['server_info']['ip'] ?? null;
        $server_hostname = $health_data['checks']['connectivity']['server_info']['hostname'] ?? null;
    }
    
    // Fallback to device IP if no server IP
    if (!$server_ip) {
        $server_ip = $ip;
    }
    
    // Process checks
    if (isset($health_data['checks'])) {
        foreach ($health_data['checks'] as $check_name => $check_data) {
            switch ($check_name) {
                case 'system:cpu':
                    $cpu_load_avg = $check_data['observedValue'] ?? null;
                    break;
                    
                case 'system:memory':
                    $memory_percent = $check_data['observedValue'] ?? null;
                    $memory_total_bytes = $check_data['memory_total_bytes'] ?? null;
                    $memory_used_bytes = $check_data['memory_used_bytes'] ?? null;
                    break;
                    
                case 'atlas:registration':
                    $atlas_registered = ($check_data['status'] ?? '') === 'pass' && ($check_data['registered'] ?? false);
                    break;
                    
                case 'service:pod':
                    $pod_status = ($check_data['status'] ?? '') === 'pass' ? ($check_data['observedValue'] ?? 'active') : 'inactive';
                    break;
                    
                case 'service:xandminer':
                    $xandminer_status = ($check_data['status'] ?? '') === 'pass' ? ($check_data['observedValue'] ?? 'active') : 'inactive';
                    break;
                    
                case 'service:xandminerd':
                    $xandminerd_status = ($check_data['status'] ?? '') === 'pass' ? ($check_data['observedValue'] ?? 'active') : 'inactive';
                    break;
            }
        }
    }
    
    // Insert the complete record
    $stmt = $pdo->prepare("
        INSERT INTO device_status_log (
            device_id, status, check_time, response_time, check_method, error_message, 
            health_status, atlas_registered, pod_status, xandminer_status, 
            xandminerd_status, cpu_load_avg, memory_percent, memory_total_bytes,
            memory_used_bytes, server_ip, server_hostname, chillxand_version,
            pod_version, xandminer_version, xandminerd_version, health_json,
            consecutive_failures
        ) VALUES (
            :device_id, :status, NOW(), :response_time, :check_method, :error_message,
            :health_status, :atlas_registered, :pod_status, :xandminer_status,
            :xandminerd_status, :cpu_load_avg, :memory_percent, :memory_total_bytes,
            :memory_used_bytes, :server_ip, :server_hostname, :chillxand_version,
            :pod_version, :xandminer_version, :xandminerd_version, :health_json,
            :consecutive_failures
        )
    ");
    
    $stmt->execute([
        ':device_id' => $device_id,
        ':status' => $status,
        ':response_time' => $response_time,
        ':check_method' => 'manual',
        ':error_message' => null,
        ':health_status' => $health_status,
        ':atlas_registered' => $atlas_registered,
        ':pod_status' => $pod_status,
        ':xandminer_status' => $xandminer_status,
        ':xandminerd_status' => $xandminerd_status,
        ':cpu_load_avg' => $cpu_load_avg,
        ':memory_percent' => $memory_percent,
        ':memory_total_bytes' => $memory_total_bytes,
        ':memory_used_bytes' => $memory_used_bytes,
        ':server_ip' => $server_ip,
        ':server_hostname' => $server_hostname,
        ':chillxand_version' => $chillxand_version,
        ':pod_version' => $pod_version,
        ':xandminer_version' => $xandminer_version,
        ':xandminerd_version' => $xandminerd_version,
        ':health_json' => json_encode($health_data),
        ':consecutive_failures' => 0
    ]);
    
    // Return success response
    echo json_encode([
        'success' => true,
        'status' => $status,
        'health_status' => $health_status,
        'response_time' => round($response_time * 1000, 1),
        'consecutive_failures' => 0,
        'timestamp' => date('M j, H:i')
    ]);
    
} catch (Exception $e) {
    echo json_encode([
        'error' => 'Check failed: ' . $e->getMessage()
    ]);
}
?>