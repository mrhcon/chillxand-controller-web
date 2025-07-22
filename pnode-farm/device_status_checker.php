<?php
/**
 * device_status_checker.php - Background Device Status Checker (Health Endpoint)
 * 
 * Run this script via cron every 5-15 minutes:
 * */5 * * * * /usr/bin/php /path/to/your/app/device_status_checker.php >> /var/log/device_checker.log 2>&1
 */

ini_set('display_errors', 0);
error_reporting(E_ALL);
set_time_limit(300); // 5 minutes max execution
ini_set('memory_limit', '128M');

// Ensure this script runs only from CLI or cron
if (PHP_SAPI !== 'cli' && !isset($_GET['force_web'])) {
    die('This script should only be run from command line or cron.');
}

require_once __DIR__ . '/db_connect.php';

if (!isset($pdo) || $pdo === null) {
    error_log("Device Status Checker: Database connection failed");
    exit(1);
}

echo "[" . date('Y-m-d H:i:s') . "] Device Status Checker started\n";

/**
 * Enhanced ping function for background checking
 */
function checkDeviceStatus($ip, $timeout = 3) {
    $start_time = microtime(true);
    $result = [
        'status' => 'Unknown',
        'response_time' => null,
        'method' => 'none',
        'error' => null
    ];
    
    // Validate IP
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        $result['status'] = 'Error';
        $result['error'] = 'Invalid IP address';
        return $result;
    }
    
    // Method 1: Try fsockopen on port 3001
    $connection = @fsockopen($ip, 3001, $errno, $errstr, $timeout);
    if ($connection) {
        fclose($connection);
        $result['status'] = 'Online';
        $result['response_time'] = microtime(true) - $start_time;
        $result['method'] = 'fsockopen';
        return $result;
    }
    
    // Method 2: Try fsockopen on port 443 (HTTPS)
    $connection = @fsockopen($ip, 443, $errno, $errstr, $timeout);
    if ($connection) {
        fclose($connection);
        $result['status'] = 'Online';
        $result['response_time'] = microtime(true) - $start_time;
        $result['method'] = 'fsockopen:443';
        return $result;
    }
    
    // Method 3: Try ping (if available)
    $ping_start = microtime(true);
    $ping_command = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') 
        ? "ping -n 1 -w " . ($timeout * 1000) . " $ip"
        : "ping -c 1 -W $timeout $ip 2>/dev/null";
    
    exec($ping_command, $output, $return_var);
    
    if ($return_var === 0) {
        $result['status'] = 'Online';
        $result['response_time'] = microtime(true) - $ping_start;
        $result['method'] = 'ping';
        return $result;
    }
    
    // All methods failed
    $result['status'] = 'Offline';
    $result['response_time'] = microtime(true) - $start_time;
    $result['method'] = 'fsockopen+ping';
    $result['error'] = "fsockopen: $errstr ($errno), ping failed";
    
    return $result;
}

/**
 * Fetch device health data from /health endpoint
 */
function fetchDeviceHealth($ip, $timeout = 5) {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => "http://$ip:3001/health",
        CURLOPT_CUSTOMREQUEST  => 'GET',  // <-- This is explicitly set
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_FAILONERROR => false,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_USERAGENT => 'Device-Status-Checker/1.0'  
    ]);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($response === false || $http_code !== 200 || !empty($error)) {
        return ['error' => "HTTP $http_code: $error"];
    }

    $data = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return ['error' => 'Invalid JSON: ' . json_last_error_msg()];
    }

    return $data;
}

/**
 * Parse health data and extract key metrics
 */
function parseHealthData($health_data) {
    if (isset($health_data['error'])) {
        return [
            'health_status' => 'unknown',
            'atlas_registered' => null,
            'pod_status' => 'unknown',
            'xandminer_status' => 'unknown',
            'xandminerd_status' => 'unknown',
            'cpu_load_avg' => null,
            'memory_percent' => null,
            'memory_total_bytes' => null,
            'memory_used_bytes' => null,
            'server_ip' => null,
            'server_hostname' => null,
            'chillxand_version' => null,
            'node_version' => null,
            'error' => $health_data['error']
        ];
    }
    
    $result = [
        'health_status' => $health_data['status'] ?? 'unknown',
        'node_version' => $health_data['version'] ?? null,
        'chillxand_version' => $health_data['chillxand_controller_version'] ?? null,
        'server_ip' => $health_data['server_info']['ip'] ?? null,
        'server_hostname' => $health_data['server_info']['hostname'] ?? null,
        'atlas_registered' => null,
        'pod_status' => 'unknown',
        'xandminer_status' => 'unknown', 
        'xandminerd_status' => 'unknown',
        'cpu_load_avg' => null,
        'memory_percent' => null,
        'memory_total_bytes' => null,
        'memory_used_bytes' => null,
        'error' => null
    ];
    
    // Parse checks array
    if (isset($health_data['checks']) && is_array($health_data['checks'])) {
        foreach ($health_data['checks'] as $check_name => $check_data) {
            switch ($check_name) {
                case 'system:cpu':
                    if (isset($check_data['observedValue'])) {
                        $result['cpu_load_avg'] = (float)$check_data['observedValue'];
                    }
                    break;
                    
                case 'system:memory':
                    if (isset($check_data['observedValue'])) {
                        $result['memory_percent'] = (float)$check_data['observedValue'];
                    }
                    if (isset($check_data['memory_total_bytes'])) {
                        $result['memory_total_bytes'] = (int)$check_data['memory_total_bytes'];
                    }
                    if (isset($check_data['memory_used_bytes'])) {
                        $result['memory_used_bytes'] = (int)$check_data['memory_used_bytes'];
                    }
                    break;
                    
                case 'atlas:registration':
                    $result['atlas_registered'] = isset($check_data['registered']) ? (bool)$check_data['registered'] : false;
                    break;
                    
                case 'service:pod':
                    if (isset($check_data['observedValue'])) {
                        $result['pod_status'] = strtolower($check_data['observedValue']);
                    }
                    break;
                    
                case 'service:xandminer':
                    if (isset($check_data['observedValue'])) {
                        $result['xandminer_status'] = strtolower($check_data['observedValue']);
                    }
                    break;
                    
                case 'service:xandminerd':
                    if (isset($check_data['observedValue'])) {
                        $result['xandminerd_status'] = strtolower($check_data['observedValue']);
                    }
                    break;
            }
        }
    }
    
    return $result;
}

// Main execution
try {
    // Get devices that need checking (haven't been checked in last 5 minutes)
    $stmt = $pdo->prepare("
        SELECT d.id, d.pnode_name, d.pnode_ip, d.username,
               latest.last_check, latest.consecutive_failures
        FROM devices d
        LEFT JOIN (
            SELECT device_id, 
                   MAX(check_time) as last_check,
                   consecutive_failures
            FROM device_status_log 
            GROUP BY device_id
        ) latest ON d.id = latest.device_id
        WHERE latest.last_check IS NULL 
           OR latest.last_check < DATE_SUB(NOW(), INTERVAL 5 MINUTE)
        ORDER BY 
            CASE WHEN latest.last_check IS NULL THEN 0 ELSE 1 END,
            latest.last_check ASC
        LIMIT 50
    ");
    $stmt->execute();
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo "Found " . count($devices) . " devices to check\n";
    
    $checked = 0;
    $online = 0;
    $offline = 0;
    $errors = 0;
    
    foreach ($devices as $device) {
        $device_id = $device['id'];
        $ip = $device['pnode_ip'];
        $name = $device['pnode_name'];
        
        echo "Checking device {$device_id}: {$name} ({$ip})... ";
        
        // Check basic connectivity
        $status = checkDeviceStatus($ip);
        echo $status['status'] . " (" . round($status['response_time'] * 1000, 1) . "ms)";
        
        // Calculate consecutive failures
        $consecutive_failures = 0;
        if ($status['status'] === 'Offline' || $status['status'] === 'Error') {
            $consecutive_failures = ($device['consecutive_failures'] ?? 0) + 1;
        }
        
        // If online, try to get health data
        $health_data = null;
        $health_status = 'unknown';
        $atlas_registered = null;
        $pod_status = 'unknown';
        $xandminer_status = 'unknown';
        $xandminerd_status = 'unknown';
        $cpu_load_avg = null;
        $memory_percent = null;
        $memory_total_bytes = null;
        $memory_used_bytes = null;
        $server_ip = null;
        $server_hostname = null;
        $chillxand_version = null;
        $node_version = null;
        $health_json = null;
        
        if ($status['status'] === 'Online') {
            echo " -> fetching health... ";
            $health_response = fetchDeviceHealth($ip);
            if (isset($health_response['error'])) {
                echo "health failed: " . $health_response['error'];
            } else {
                echo "health OK";
                $health_json = json_encode($health_response);
                
                // Parse health data
                $parsed_health = parseHealthData($health_response);
                $health_status = $parsed_health['health_status'];
                $atlas_registered = $parsed_health['atlas_registered'];
                $pod_status = $parsed_health['pod_status'];
                $xandminer_status = $parsed_health['xandminer_status'];
                $xandminerd_status = $parsed_health['xandminerd_status'];
                $cpu_load_avg = $parsed_health['cpu_load_avg'];
                $memory_percent = $parsed_health['memory_percent'];
                $memory_total_bytes = $parsed_health['memory_total_bytes'];
                $memory_used_bytes = $parsed_health['memory_used_bytes'];
                $server_ip = $parsed_health['server_ip'];
                $server_hostname = $parsed_health['server_hostname'];
                $chillxand_version = $parsed_health['chillxand_version'];
                $node_version = $parsed_health['node_version'];
            }
        }
        
        // Insert new status log entry
        $stmt = $pdo->prepare("
            INSERT INTO device_status_log (
                device_id, status, check_time, response_time, check_method, 
                error_message, consecutive_failures,
                health_status, atlas_registered, pod_status, xandminer_status, xandminerd_status,
                cpu_load_avg, memory_percent, memory_total_bytes, memory_used_bytes,
                server_ip, server_hostname, chillxand_version, node_version, health_json
            ) VALUES (?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        $success = $stmt->execute([
            $device_id,
            $status['status'],
            $status['response_time'],
            $status['method'],
            $status['error'],
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
        
        if ($success) {
            echo " -> logged";
        } else {
            echo " -> log failed";
        }
        
        echo "\n";
        
        // Update counters
        $checked++;
        switch ($status['status']) {
            case 'Online': $online++; break;
            case 'Offline': $offline++; break;
            default: $errors++; break;
        }
        
        // Small delay to avoid overwhelming network/devices
        usleep(500000); // 0.5 seconds
    }
    
    echo "\nSummary: Checked $checked devices - Online: $online, Offline: $offline, Errors: $errors\n";
    
    // Cleanup old logs (keep last 90 days)
    $stmt = $pdo->prepare("DELETE FROM device_status_log WHERE check_time < DATE_SUB(NOW(), INTERVAL 90 DAY)");
    $stmt->execute();
    $deleted = $stmt->rowCount();
    if ($deleted > 0) {
        echo "Cleaned up $deleted old log records\n";
    }
    
} catch (Exception $e) {
    error_log("Device Status Checker error: " . $e->getMessage());
    echo "Error: " . $e->getMessage() . "\n";
    exit(1);
}

echo "[" . date('Y-m-d H:i:s') . "] Device Status Checker completed\n";
?>