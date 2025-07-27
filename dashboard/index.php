<?php
// Start session or include necessary configurations
require_once 'includes/config.php';

// Determine which module to load based on GET parameter
$module = isset($_GET['module']) ? $_GET['module'] : 'dashboard';
$module_file = "modules/$module.php";

// Validate module file exists to prevent inclusion errors
if (!file_exists($module_file)) {
    $module_file = 'modules/dashboard.php'; // Fallback to dashboard
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Management Console</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <!-- Header -->
        <?php include 'includes/header.php'; ?>

        <div class="main">
            <!-- Left Menu -->
            <?php include 'includes/menu.php'; ?>

            <!-- Content Area -->
            <div class="content">
                <?php include $module_file; ?>
            </div>
        </div>

        <!-- Footer -->
        <?php include 'includes/footer.php'; ?>
    </div>
</body>
</html>