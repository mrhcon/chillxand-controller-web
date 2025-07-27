<?php
// Configuration settings
define('SITE_NAME', 'Network Management Console');

// Simulate a database connection (replace with actual DB logic)
function get_network_data($type) {
    // Mock data for demonstration
    $data = [
        'dashboard' => [
            'devices_online' => 45,
            'devices_offline' => 3,
            'alerts' => 2
        ],
        'devices' => [
            ['id' => 1, 'name' => 'Router-01', 'status' => 'Online', 'ip' => '192.168.1.1'],
            ['id' => 2, 'name' => 'Switch-01', 'status' => 'Offline', 'ip' => '192.168.1.2']
        ],
        'logs' => [
            ['id' => 1, 'event' => 'Device rebooted', 'time' => '2025-06-24 15:30:00'],
            ['id' => 2, 'event' => 'Connection lost', 'time' => '2025-06-24 15:32:00']
        ]
    ];
    return $data[$type] ?? [];
}
?>