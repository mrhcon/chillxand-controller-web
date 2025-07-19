<?php
session_start();
require_once 'db_connect.php';
require_once 'functions.php';

// Log logout action
if (isset($_SESSION['user_id'])) {
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'logout');
}

session_unset();
session_destroy();
header("Location: login.php");
exit();
?>