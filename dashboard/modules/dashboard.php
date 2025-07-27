<?php
$data = get_network_data('dashboard');
?>

<div class="content-panel">
    <h2>Dashboard</h2>
    <div class="dashboard-stats">
        <div class="stat-card">
            <h3>Devices Online</h3>
            <p><?php echo $data['devices_online']; ?></p>
        </div>
        <div class="stat-card">
            <h3>Devices Offline</h3>
            <p><?php echo $data['devices_offline']; ?></p>
        </div>
        <div class="stat-card">
            <h3>Active Alerts</h3>
            <p><?php echo $data['alerts']; ?></p>
        </div>
    </div>
</div>