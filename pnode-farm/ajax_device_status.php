<?php
session_start();
require_once 'db_connect.php';
require_once 'functions.php';

/**
 * Format uptime seconds into human readable format
 */
function formatUptime($seconds) {
    if (!$seconds || $seconds < 0) return '0s';

    $days = floor($seconds / 86400);
    $hours = floor(($seconds % 86400) / 3600);
    $minutes = floor(($seconds % 3600) / 60);
    $secs = $seconds % 60;

    $parts = [];
    if ($days > 0) $parts[] = $days . 'd';
    if ($hours > 0) $parts[] = $hours . 'h';
    if ($minutes > 0) $parts[] = $minutes . 'm';
    if ($secs > 0 || empty($parts)) $parts[] = $secs . 's';

    return implode(' ', $parts);
}

// Set content type to JSON
header('Content-Type: application/json');

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Not authenticated']);
    exit();
}

// Fetch admin status and enforce admin access
if (!isset($_SESSION['admin'])) {
    try {
        $stmt = $pdo->prepare("SELECT admin FROM users WHERE id = :user_id");
        $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
        $stmt->execute();
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        $_SESSION['admin'] = $user['admin'] ?? 0;
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Database error fetching user details']);
        exit();
    }
}

// Enforce admin access
if (!$_SESSION['admin']) {
    http_response_code(403);
    echo json_encode(['error' => 'Admin access required']);
    exit();
}

// Get device ID from request
$device_id = $_GET['device_id'] ?? null;
if (!$device_id) {
    http_response_code(400);
    echo json_encode(['error' => 'Device ID required']);
    exit();
}

try {
    // Get device (admin can access any device)
    $stmt = $pdo->prepare("SELECT id, pnode_name, pnode_ip, username FROM devices WHERE id = ?");
    $stmt->execute([$device_id]);
    $device = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$device) {
        http_response_code(404);
        echo json_encode(['error' => 'Device not found']);
        exit();
    }

    // Get latest status for this device
    $cached_statuses = getLatestDeviceStatuses($pdo, [$device_id]);
    $cached_status = $cached_statuses[$device_id] ?? [
        'status' => 'Not Initialized',
        'is_stale' => true,
        'error_message' => 'Device has not been checked yet'
    ];

    // Parse health data
    $summary = parseCachedDeviceHealth($cached_status);

    // Determine overall status (must match the logic from dashboard.php and devices.php)
    $overall_status = 'Unknown';
    if ($cached_status['status'] === 'Online') {
        if ($summary['health_status'] === 'pass') {
            $overall_status = 'Healthy';
        } elseif ($summary['health_status'] === 'fail') {
            $overall_status = 'Online (Issues)';
        } else {
            $overall_status = 'Online';
        }
    } elseif ($cached_status['status'] === 'Offline') {
        $overall_status = 'Offline';
    } else {
        $overall_status = $cached_status['status'];
    }

    // Build pNode stats from cached data (no additional DB queries!)
    $pnode_stats = null;
    if ($cached_status['status'] === 'Online' && $cached_status['stats_cpu_percent'] !== null) {
        $pnode_stats = [
            // Main display stats (for compatibility with existing UI)
            'cpu_percent' => $cached_status['stats_cpu_percent'],
            'memory_percent' => (($cached_status['stats_ram_used'] ?? 0) / max($cached_status['stats_ram_total'] ?? 1, 1)) * 100,
            'total_bytes_transferred' => $cached_status['stats_total_bytes'] ?? 0,
            'total_pages' => $cached_status['stats_total_pages'] ?? 0,
            'packets_received' => $cached_status['stats_packets_received'] ?? 0,
            'packets_sent' => $cached_status['stats_packets_sent'] ?? 0,

            // ALL additional stats from the stats section
            'current_index' => $cached_status['stats_current_index'] ?? 0,
            'last_updated' => $cached_status['stats_last_updated'] ?? 0,
            'ram_used' => $cached_status['stats_ram_used'] ?? 0,
            'ram_total' => $cached_status['stats_ram_total'] ?? 0,
            'uptime' => $cached_status['stats_uptime'] ?? 0,
            'active_streams' => $cached_status['stats_active_streams'] ?? 0,
            'file_size' => $cached_status['stats_file_size'] ?? 0,

            // Raw stats fields (direct database access)
            'stats_current_index' => $cached_status['stats_current_index'] ?? 0,
            'stats_total_pages' => $cached_status['stats_total_pages'] ?? 0,
            'stats_last_updated' => $cached_status['stats_last_updated'] ?? 0,
            'stats_total_bytes' => $cached_status['stats_total_bytes'] ?? 0,
            'stats_cpu_percent' => $cached_status['stats_cpu_percent'] ?? 0,
            'stats_ram_used' => $cached_status['stats_ram_used'] ?? 0,
            'stats_ram_total' => $cached_status['stats_ram_total'] ?? 0,
            'stats_uptime' => $cached_status['stats_uptime'] ?? 0,
            'stats_packets_sent' => $cached_status['stats_packets_sent'] ?? 0,
            'stats_packets_received' => $cached_status['stats_packets_received'] ?? 0,
            'stats_active_streams' => $cached_status['stats_active_streams'] ?? 0,
            'stats_file_size' => $cached_status['stats_file_size'] ?? 0,

            // Additional computed/formatted values
            'uptime_formatted' => formatUptime($cached_status['stats_uptime'] ?? 0),
            'file_size_formatted' => formatBytesForDisplay($cached_status['stats_file_size'] ?? 0),
            'ram_used_formatted' => formatBytesForDisplay($cached_status['stats_ram_used'] ?? 0),
            'ram_total_formatted' => formatBytesForDisplay($cached_status['stats_ram_total'] ?? 0),
            'total_bytes_formatted' => formatBytesForDisplay($cached_status['stats_total_bytes'] ?? 0),
            'last_updated_formatted' => $cached_status['stats_last_updated'] ? date('Y-m-d H:i:s', $cached_status['stats_last_updated']) : 'N/A'
        ];
    }

    // Return JSON response
    echo json_encode([
        'success' => true,
        'device_id' => $device_id,
        'status' => $cached_status['status'],
        'overall_status' => $overall_status,
        'status_age' => $cached_status['age_minutes'],
        'status_stale' => $cached_status['is_stale'],
        'last_check' => $cached_status['check_time'],
        'response_time' => $cached_status['response_time'],
        'consecutive_failures' => $cached_status['consecutive_failures'],
        'health_status' => $cached_status['health_status'],
        'summary' => $summary,
        'pnode_stats' => $pnode_stats,
        'timestamp' => date('M j, H:i', time())
    ]);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}
?>