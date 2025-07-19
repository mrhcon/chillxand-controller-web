<?php
$details = "Device IP: 194.233.90.20, Port: 80, Timeout: 2s, fsockopen Time: 0.208s, fsockopen Error: Connection refused (111), Ping Time: 0.211s, Status: Online, Method: ping";
if (preg_match("/(?:Device )?IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/", $details, $matches)) {
    echo "IP: " . $matches[1];
} else {
    echo "No IP found";
}
?>