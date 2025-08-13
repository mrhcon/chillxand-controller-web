<?php
// manual_device_check.php - Fixed version
session_start();

// Clean any previous output and set proper headers
ob_clean();
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
    $stats_current_index = null;
    $stats_total_pages = null;
    $stats_last_updated = null;
    $stats_total_bytes = null;
    $stats_cpu_percent = null;
    $stats_ram_used = null;
    $stats_ram_total = null;
    $stats_uptime = null;
    $stats_packets_sent = null;
    $stats_packets_received = null;
    $stats_active_streams = null;
    $stats_file_size = null;

    // Test connectivity
    $ip = $device['pnode_ip'];
    $port = 3001;

    // Helper function to get cached data
    function getCachedHealthData($pdo, $device_id) {
        try {
            $cached_statuses = getLatestDeviceStatuses($pdo, [$device_id]);
            $cached_status = $cached_statuses[$device_id] ?? null;
            $cached_health = [];
            if ($cached_status) {
                $cached_health = parseCachedDeviceHealth($cached_status);
            }
            return $cached_health;
        } catch (Exception $e) {
            error_log("Error getting cached status: " . $e->getMessage());
            return [];
        }
    }

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
                consecutive_failures, stats_current_index, stats_total_pages, stats_last_updated,
                stats_total_bytes, stats_cpu_percent, stats_ram_used, stats_ram_total,
                stats_uptime, stats_packets_sent, stats_packets_received, stats_active_streams,
                stats_file_size
            ) VALUES (
                :device_id, :status, NOW(), :response_time, :check_method, :error_message,
                :health_status, :atlas_registered, :pod_status, :xandminer_status,
                :xandminerd_status, :cpu_load_avg, :memory_percent, :memory_total_bytes,
                :memory_used_bytes, :server_ip, :server_hostname, :chillxand_version,
                :pod_version, :xandminer_version, :xandminerd_version, :health_json,
                :consecutive_failures, :stats_current_index, :stats_total_pages, :stats_last_updated,
                :stats_total_bytes, :stats_cpu_percent, :stats_ram_used, :stats_ram_total,
                :stats_uptime, :stats_packets_sent, :stats_packets_received, :stats_active_streams,
                :stats_file_size
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
            ':consecutive_failures' => 0,
            ':stats_current_index' => null,
            ':stats_total_pages' => null,
            ':stats_last_updated' => null,
            ':stats_total_bytes' => null,
            ':stats_cpu_percent' => null,
            ':stats_ram_used' => null,
            ':stats_ram_total' => null,
            ':stats_uptime' => null,
            ':stats_packets_sent' => null,
            ':stats_packets_received' => null,
            ':stats_active_streams' => null,
            ':stats_file_size' => null
        ]);

        // Get cached data to return
        $cached_health = getCachedHealthData($pdo, $device_id);

        echo json_encode([
            'success' => true,
            'status' => 'Offline',
            'response_time' => 0,
            'consecutive_failures' => 0,
            'timestamp' => date('M j, H:i'),
            'health_data' => [
                'health_status' => $cached_health['health_status'] ?? 'unknown',
                'atlas_registered' => $cached_health['atlas_registered'] ?? false,
                'pod_status' => $cached_health['pod_status'] ?? 'unknown',
                'xandminer_status' => $cached_health['xandminer_status'] ?? 'unknown',
                'xandminerd_status' => $cached_health['xandminerd_status'] ?? 'unknown'
            ],
            'version_data' => [
                'chillxand_version' => $cached_health['chillxand_version'] ?? 'N/A',
                'pod_version' => $cached_health['pod_version'] ?? 'N/A',
                'xandminer_version' => $cached_health['xandminer_version'] ?? 'N/A',
                'xandminerd_version' => $cached_health['xandminerd_version'] ?? 'N/A'
            ]
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
                consecutive_failures, stats_current_index, stats_total_pages, stats_last_updated,
                stats_total_bytes, stats_cpu_percent, stats_ram_used, stats_ram_total,
                stats_uptime, stats_packets_sent, stats_packets_received, stats_active_streams,
                stats_file_size
            ) VALUES (
                :device_id, :status, NOW(), :response_time, :check_method, :error_message,
                :health_status, :atlas_registered, :pod_status, :xandminer_status,
                :xandminerd_status, :cpu_load_avg, :memory_percent, :memory_total_bytes,
                :memory_used_bytes, :server_ip, :server_hostname, :chillxand_version,
                :pod_version, :xandminer_version, :xandminerd_version, :health_json,
                :consecutive_failures, :stats_current_index, :stats_total_pages, :stats_last_updated,
                :stats_total_bytes, :stats_cpu_percent, :stats_ram_used, :stats_ram_total,
                :stats_uptime, :stats_packets_sent, :stats_packets_received, :stats_active_streams,
                :stats_file_size
            )
        ");

        $stmt->execute([
            ':device_id' => $device_id,
            ':status' => 'Online',
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
            ':consecutive_failures' => 0,
            ':stats_current_index' => null,
            ':stats_total_pages' => null,
            ':stats_last_updated' => null,
            ':stats_total_bytes' => null,
            ':stats_cpu_percent' => null,
            ':stats_ram_used' => null,
            ':stats_ram_total' => null,
            ':stats_uptime' => null,
            ':stats_packets_sent' => null,
            ':stats_packets_received' => null,
            ':stats_active_streams' => null,
            ':stats_file_size' => null
        ]);

        // Get cached data for error response
        $cached_health = getCachedHealthData($pdo, $device_id);

        echo json_encode([
            'success' => true,
            'status' => 'Online',
            'response_time' => round($response_time * 1000, 1),
            'consecutive_failures' => 0,
            'timestamp' => date('M j, H:i'),
            'health_data' => [
                'health_status' => $cached_health['health_status'] ?? 'unknown',
                'atlas_registered' => $cached_health['atlas_registered'] ?? false,
                'pod_status' => $cached_health['pod_status'] ?? 'unknown',
                'xandminer_status' => $cached_health['xandminer_status'] ?? 'unknown',
                'xandminerd_status' => $cached_health['xandminerd_status'] ?? 'unknown'
            ],
            'version_data' => [
                'chillxand_version' => $cached_health['chillxand_version'] ?? 'N/A',
                'pod_version' => $cached_health['pod_version'] ?? 'N/A',
                'xandminer_version' => $cached_health['xandminer_version'] ?? 'N/A',
                'xandminerd_version' => $cached_health['xandminerd_version'] ?? 'N/A'
            ]
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
                consecutive_failures, stats_current_index, stats_total_pages, stats_last_updated,
                stats_total_bytes, stats_cpu_percent, stats_ram_used, stats_ram_total,
                stats_uptime, stats_packets_sent, stats_packets_received, stats_active_streams,
                stats_file_size
            ) VALUES (
                :device_id, :status, NOW(), :response_time, :check_method, :error_message,
                :health_status, :atlas_registered, :pod_status, :xandminer_status,
                :xandminerd_status, :cpu_load_avg, :memory_percent, :memory_total_bytes,
                :memory_used_bytes, :server_ip, :server_hostname, :chillxand_version,
                :pod_version, :xandminer_version, :xandminerd_version, :health_json,
                :consecutive_failures, :stats_current_index, :stats_total_pages, :stats_last_updated,
                :stats_total_bytes, :stats_cpu_percent, :stats_ram_used, :stats_ram_total,
                :stats_uptime, :stats_packets_sent, :stats_packets_received, :stats_active_streams,
                :stats_file_size
            )
        ");

        $stmt->execute([
            ':device_id' => $device_id,
            ':status' => 'Online',
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
            ':consecutive_failures' => 0,
            ':stats_current_index' => null,
            ':stats_total_pages' => null,
            ':stats_last_updated' => null,
            ':stats_total_bytes' => null,
            ':stats_cpu_percent' => null,
            ':stats_ram_used' => null,
            ':stats_ram_total' => null,
            ':stats_uptime' => null,
            ':stats_packets_sent' => null,
            ':stats_packets_received' => null,
            ':stats_active_streams' => null,
            ':stats_file_size' => null
        ]);

        // Get cached data for JSON parse error
        $cached_health = getCachedHealthData($pdo, $device_id);

        echo json_encode([
            'success' => true,
            'status' => 'Online',
            'response_time' => round($response_time * 1000, 1),
            'consecutive_failures' => 0,
            'timestamp' => date('M j, H:i'),
            'health_data' => [
                'health_status' => $cached_health['health_status'] ?? 'unknown',
                'atlas_registered' => $cached_health['atlas_registered'] ?? false,
                'pod_status' => $cached_health['pod_status'] ?? 'unknown',
                'xandminer_status' => $cached_health['xandminer_status'] ?? 'unknown',
                'xandminerd_status' => $cached_health['xandminerd_status'] ?? 'unknown'
            ],
            'version_data' => [
                'chillxand_version' => $cached_health['chillxand_version'] ?? 'N/A',
                'pod_version' => $cached_health['pod_version'] ?? 'N/A',
                'xandminer_version' => $cached_health['xandminer_version'] ?? 'N/A',
                'xandminerd_version' => $cached_health['xandminerd_version'] ?? 'N/A'
            ]
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

    // Parse stats data from health response
    if (isset($health_data['stats']) && is_array($health_data['stats'])) {
        $stats = $health_data['stats'];
        $stats_current_index = $stats['current_index'] ?? null;
        $stats_total_pages = $stats['total_pages'] ?? null;
        $stats_last_updated = $stats['last_updated'] ?? null;
        $stats_total_bytes = $stats['total_bytes'] ?? null;
        $stats_cpu_percent = $stats['cpu_percent'] ?? null;
        $stats_ram_used = $stats['ram_used'] ?? null;
        $stats_ram_total = $stats['ram_total'] ?? null;
        $stats_uptime = $stats['uptime'] ?? null;
        $stats_packets_sent = $stats['packets_sent'] ?? null;
        $stats_packets_received = $stats['packets_received'] ?? null;
        $stats_active_streams = $stats['active_streams'] ?? null;
        $stats_file_size = $stats['file_size'] ?? null;
    }

    // Insert the complete record
    $stmt = $pdo->prepare("
        INSERT INTO device_status_log (
            device_id, status, check_time, response_time, check_method, error_message,
            health_status, atlas_registered, pod_status, xandminer_status,
            xandminerd_status, cpu_load_avg, memory_percent, memory_total_bytes,
            memory_used_bytes, server_ip, server_hostname, chillxand_version,
            pod_version, xandminer_version, xandminerd_version, health_json,
            consecutive_failures, stats_current_index, stats_total_pages, stats_last_updated,
            stats_total_bytes, stats_cpu_percent, stats_ram_used, stats_ram_total,
            stats_uptime, stats_packets_sent, stats_packets_received, stats_active_streams,
            stats_file_size
        ) VALUES (
            :device_id, :status, NOW(), :response_time, :check_method, :error_message,
            :health_status, :atlas_registered, :pod_status, :xandminer_status,
            :xandminerd_status, :cpu_load_avg, :memory_percent, :memory_total_bytes,
            :memory_used_bytes, :server_ip, :server_hostname, :chillxand_version,
            :pod_version, :xandminer_version, :xandminerd_version, :health_json,
            :consecutive_failures, :stats_current_index, :stats_total_pages, :stats_last_updated,
            :stats_total_bytes, :stats_cpu_percent, :stats_ram_used, :stats_ram_total,
            :stats_uptime, :stats_packets_sent, :stats_packets_received, :stats_active_streams,
            :stats_file_size
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
        ':consecutive_failures' => 0,
        ':stats_current_index' => $stats_current_index,
        ':stats_total_pages' => $stats_total_pages,
        ':stats_last_updated' => $stats_last_updated,
        ':stats_total_bytes' => $stats_total_bytes,
        ':stats_cpu_percent' => $stats_cpu_percent,
        ':stats_ram_used' => $stats_ram_used,
        ':stats_ram_total' => $stats_ram_total,
        ':stats_uptime' => $stats_uptime,
        ':stats_packets_sent' => $stats_packets_sent,
        ':stats_packets_received' => $stats_packets_received,
        ':stats_active_streams' => $stats_active_streams,
        ':stats_file_size' => $stats_file_size
    ]);

    // Get the cached status data to return the same info as the main page
    $cached_statuses = getLatestDeviceStatuses($pdo, [$device_id]);
    $cached_status = $cached_statuses[$device_id] ?? null;

    // Parse cached health data
    $cached_health = [];
    if ($cached_status) {
        $cached_health = parseCachedDeviceHealth($cached_status);
    }

    // For successful connectivity, return the fresh data we just collected
    // Connectivity status is ONLY about whether we can reach the device

    // Add debugging output
    error_log("DEBUG: Device $device_id final response - Status: 'Online', Health: '$health_status', Response time: " . round($response_time * 1000, 1) . "ms");

    $response_data = [
        'success' => true,
        'status' => 'Online',  // Always "Online" if we got here (port 3001 responded)
        'health_status' => $health_status,
        'response_time' => round($response_time * 1000, 1),
        'consecutive_failures' => 0,
        'timestamp' => date('M j, H:i'),
        'debug_info' => [
            'device_id' => $device_id,
            'device_ip' => $ip,
            'port_connected' => true,
            'health_json_received' => !empty($health_data),
            'health_json_size' => strlen(json_encode($health_data ?? [])),
            'php_version' => PHP_VERSION,
            'current_time' => date('Y-m-d H:i:s')
        ],
        'health_data' => [
            'health_status' => $health_status ?: 'unknown',
            'atlas_registered' => $atlas_registered,
            'pod_status' => $pod_status ?: 'unknown',
            'xandminer_status' => $xandminer_status ?: 'unknown',
            'xandminerd_status' => $xandminerd_status ?: 'unknown'
        ],
        'version_data' => [
            'chillxand_version' => $chillxand_version ?: 'N/A',
            'pod_version' => $pod_version ?: 'N/A',
            'xandminer_version' => $xandminer_version ?: 'N/A',
            'xandminerd_version' => $xandminerd_version ?: 'N/A'
        ]
    ];

    // Extract pNode stats data from health response
    $pnode_stats = null;
    if (isset($health_data['stats']) && is_array($health_data['stats'])) {
        $stats = $health_data['stats'];
        $pnode_stats = [
            'cpu_percent' => $stats['cpu_percent'] ?? null,
            'memory_percent' => null, // Calculate from ram_used/ram_total
            'total_bytes_transferred' => $stats['total_bytes'] ?? 0,
            'total_pages' => $stats['total_pages'] ?? 0,
            'current_index' => $stats['current_index'] ?? 0,
            'ram_used' => $stats['ram_used'] ?? 0,
            'ram_total' => $stats['ram_total'] ?? 0,
            'uptime' => $stats['uptime'] ?? 0,
            'active_streams' => $stats['active_streams'] ?? 0,
            'file_size' => $stats['file_size'] ?? 0,
            'packets_received' => $stats['packets_received'] ?? 0,
            'packets_sent' => $stats['packets_sent'] ?? 0
        ];

        // Calculate memory percentage
        if ($stats['ram_used'] && $stats['ram_total'] && $stats['ram_total'] > 0) {
            $pnode_stats['memory_percent'] = ($stats['ram_used'] / $stats['ram_total']) * 100;
        }
    }

    // Add pnode_stats to the response
    $response_data['pnode_stats'] = $pnode_stats;

    error_log("DEBUG: Final JSON response: " . json_encode($response_data));

    echo json_encode($response_data);

} catch (Exception $e) {
    echo json_encode([
        'error' => 'Check failed: ' . $e->getMessage()
    ]);
}
?>