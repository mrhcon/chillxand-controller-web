<?php
$devices = get_network_data('devices');
?>

<div class="content-panel">
    <h2>Devices</h2>
    <table class="device-table">
        <thead>
            <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Status</th>
                <th>IP Address</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($devices as $device): ?>
                <tr>
                    <td><?php echo $device['id']; ?></td>
                    <td><?php echo $device['name']; ?></td>
                    <td class="<?php echo strtolower($device['status']); ?>">
                        <?php echo $device['status']; ?>
                    </td>
                    <td><?php echo $device['ip']; ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>