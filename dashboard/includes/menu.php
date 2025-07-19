<aside class="sidebar">
    <ul class="menu">
        <li><a href="menu.php?module=dashboard" <?php echo $module === 'dashboard' ? 'class="active"' : ''; ?>>Dashboard</a></li>
        <li><a href="menu.php?module=devices" <?php echo $module === 'devices' ? 'class="active"' : ''; ?>>Devices</a></li>
        <li><a href="menu.php?module=logs" <?php echo $module === 'logs' ? 'class="active"' : ''; ?>>Logs</a></li>
    </ul>
</aside>