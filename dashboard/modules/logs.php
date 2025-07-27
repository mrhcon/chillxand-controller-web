<?php
$logs = get_network_data('logs');
?>

<div class="content-panel">
    <h2>Logs</h2>
    <table class="log-table">
        <thead>
            <tr>
                <th>ID</th>
                <th>Event</th>
                <th>Time</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($logs as $log): ?>
                <tr>
                    <td><?php echo $log['id']; ?></td>
                    <td><?php echo $log['event']; ?></td>
                    <td><?php echo $log['time']; ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>