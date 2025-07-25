<?php
// manual_device_check.php - Fixed version with proper column mapping
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
    
    error_log("Checking device ID: {$device['id']}");
    error_log("Found device: {$device['pnode_name']} at {$device['pnode_ip']}");
    
    // Test connectivity
    $ip = $device['pnode_ip'];
    $port = 3001;
    
    error_log("Testing connectivity to {$ip}:{$port}");
    
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
    error_log("Port {$port} is open, fetching health data");
    
    // Get health data
    $url = "http://{$ip}:{$port}/health";
    error_log("Making request to: {$url}");
    
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
        $http_error = error_get_last()['message'] ?? 'Unknown HTTP error';
        error_log("Health error: {$http_error}");
        
        // HTTP request failed but port was open - partial connectivity
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
            ':error_message' => "HTTP request failed: {$http_error}",
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
    
    error_log("Health HTTP code: 200");
    error_log("Health error: none");
    error_log("Response length: " . strlen($response));
    error_log("Response preview: " . substr($response, 0, 200) . "...");
    
    // Parse JSON response
    $health_data = json_decode($response, true);
    if ($health_data === null) {
        error_log("JSON decode failed: " . json_last_error_msg());
        
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
            ':error_message' => 'Invalid JSON response from health endpoint',
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
    
    error_log("JSON decode result: SUCCESS");
    error_log("Health data keys: " . implode(', ', array_keys($health_data)));
    
    // Extract health information with safe defaults
    $status = 'Online';
    $health_status = $health_data['status'] ?? null;
    $chillxand_version = null;
    $atlas_registered = false;
    $pod_status = null;
    $xandminer_status = null;
    $xandminerd_status = null;
    $cpu_load_avg = null;
    $memory_percent = null;
    
    // Extract ChillXand version (try multiple paths)
    if (isset($health_data['chillxand_controller_version'])) {
        $chillxand_version = $health_data['chillxand_controller_version'];
    } elseif (isset($health_data['versions']['data']['chillxand_controller'])) {
        $chillxand_version = $health_data['versions']['data']['chillxand_controller'];
    }
    
    error_log("Basic health: status={$health_status}, chillxand={$chillxand_version}");
    
    // Process checks if available
    if (isset($health_data['checks']) && is_array($health_data['checks'])) {
        error_log("Found " . count($health_data['checks']) . " checks");
        error_log("Check names: " . implode(', ', array_keys($health_data['checks'])));
        
        foreach ($health_data['checks'] as $check_name => $check_data) {
            switch ($check_name) {
                case 'system:cpu':
                    if (isset($check_data['load_average'])) {
                        $cpu_load_avg = (float)$check_data['load_average'];
                        error_log("CPU load: {$cpu_load_avg}");
                    }
                    break;
                    
                case 'system:memory':
                    if (isset($check_data['percent'])) {
                        $memory_percent = (float)$check_data['percent'];
                        error_log("Memory percent: {$memory_percent}");
                    }
                    if (isset($check_data['total'])) {
                        error_log("Memory total: {$check_data['total']}");
                    }
                    if (isset($check_data['used'])) {
                        error_log("Memory used: {$check_data['used']}");
                    }
                    break;
                    
                case 'atlas:registration':
                    $atlas_registered = ($check_data['status'] ?? '') === 'pass';
                    error_log("Atlas registered: " . ($atlas_registered ? 'true' : 'false'));
                    break;
                    
                case 'service:pod':
                    $pod_status = $check_data['status'] ?? null;
                    if ($pod_status === 'pass') {
                        $pod_status = 'active';
                    } elseif ($pod_status === 'fail') {
                        $pod_status = isset($check_data['activating']) && $check_data['activating'] ? 'activating' : 'inactive';
                    }
                    error_log("Pod status: {$pod_status}");
                    break;
                    
                case 'service:xandminer':
                    $xandminer_status = ($check_data['status'] ?? '') === 'pass' ? 'active' : 'inactive';
                    error_log("Xandminer status: {$xandminer_status}");
                    break;
                    
                case 'service:xandminerd':
                    $xandminerd_status = ($check_data['status'] ?? '') === 'pass' ? 'active' : 'inactive';
                    error_log("Xandminerd status: {$xandminerd_status}");
                    break;
            }
        }
    }
    
    error_log("About to insert into database...");
    error_log("Values: health_status={$health_status}, atlas={$atlas_registered}, pod={$pod_status}, xandminer={$xandminer_status}, xandminerd={$xandminerd_status}");
    
    // Extract additional data for the full table structure
    $memory_total_bytes = null;
    $memory_used_bytes = null;
    $server_ip = $ip; // Use the device IP as fallback
    $server_hostname = null;
    $pod_version = null;
    $xandminer_version = null;
    $xandminerd_version = null;
    
    // Extract version information from the versions section
    if (isset($health_data['versions']['data']) && is_array($health_data['versions']['data'])) {
        $versions = $health_data['versions']['data'];
        $pod_version = $versions['pod'] ?? null;
        $xandminer_version = $versions['xandminer'] ?? null;  // This might not exist in response
        $xandminerd_version = $versions['xandminerd'] ?? null;
        error_log("Extracted versions: pod={$pod_version}, xandminer={$xandminer_version}, xandminerd={$xandminerd_version}");
    }
    
    // Extract server info from connectivity check (this is where the real server info is)
    if (isset($health_data['checks']['connectivity']['server_info'])) {
        $server_info = $health_data['checks']['connectivity']['server_info'];
        $server_ip = $server_info['ip'] ?? $ip;
        $server_hostname = $server_info['hostname'] ?? null;
        error_log("Server info: ip={$server_ip}, hostname={$server_hostname}");
    }
    
    // Also try atlas registration for server info as backup
    if (!$server_hostname && isset($health_data['checks']['atlas:registration']['server_info'])) {
        $server_info = $health_data['checks']['atlas:registration']['server_info'];
        $server_ip = $server_info['ip'] ?? $server_ip;
        $server_hostname = $server_info['hostname'] ?? $server_hostname;
        error_log("Atlas server info: ip={$server_ip}, hostname={$server_hostname}");
    }
    
    // Insert the complete record with ALL table columns
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
    
    $result = $stmt->execute([
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
    
    if (!$result) {
        $error_info = $stmt->errorInfo();
        error_log("Database insert failed: " . print_r($error_info, true));
        throw new Exception("Database insert failed: " . $error_info[2]);
    }
    
    error_log("Database insert successful");
    
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
    error_log("Check failed: " . $e->getMessage());
    echo json_encode([
        'error' => 'Check failed: ' . $e->getMessage(),
        'debug_info' => error_get_last()
    ]);
}