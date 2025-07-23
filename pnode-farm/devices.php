<script>
        document.addEventListener('DOMContentLoaded', function() {
            console.log('DOM loaded, initializing button handlers...');
            console.log('Button handlers initialized successfully');
        });
        
        function refreshDeviceStatus(deviceId) {
            const statusElement = document.querySelector('#status-' + deviceId);
            const refreshBtn = document.querySelector('#refresh-' + deviceId);
            const lastCheckElement = document.querySelector('#lastcheck-' + deviceId);
            
            refreshBtn.disabled = true;
            refreshBtn.textContent = '⟳';
            
            fetch('manual_device_check.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'device_id=' + deviceId
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.error) {
                    alert('Error: ' + data.error);
                } else {
                    var overallStatus = 'Unknown';
                    var statusClass = 'unknown';
                    
                    if (data.status === 'Online') {
                        statusClass = 'online';
                        overallStatus = data.status;
                    } else if (data.status === 'Offline') {
                        overallStatus = 'Offline';
                        statusClass = 'offline';
                    } else {
                        overallStatus = data.status;
                        statusClass = data.status.toLowerCase().replace(' ', '-');
                    }
                    
                    var statusHtml = '<span class="status-btn status-' + statusClass + '">' + overallStatus + '</span>';
                    statusHtml += '<button class="refresh-btn" id="refresh-' + deviceId + '" onclick="refreshDeviceStatus(' + deviceId + ')" title="Refresh status">↻</button>';
                    statusHtml += '<div class="status-age status-fresh">Just checked</div>';
                    statusHtml += '<div class="device-details">Response: ' + data.response_time + 'ms</div>';
                    if (data.consecutive_failures > 0) {
                        statusHtml += '<div class="device-details" style="color: #dc3545;">Failures: ' + data.consecutive_failures + '</div>';
                    }
                    statusElement.innerHTML = statusHtml;
                    
                    var healthElement = statusElement.parentNode.nextElementSibling;
                    if (data.status === 'Online' && data.health_status) {
                        var healthClass = data.health_status === 'pass' ? 'online' : 'offline';
                        healthElement.innerHTML = '<span class="status-btn status-' + healthClass + '">' + data.health_status.charAt(0).toUpperCase() + data.health_status.slice(1) + '</span>';
                    } else {
                        healthElement.innerHTML = '<span class="status-btn status-not-initialized">Not Initialized</span>';
                    }
                    
                    lastCheckElement.innerHTML = '<div class="status-fresh">Just now</div><div style="font-size: 10px;">' + data.timestamp + '</div>';
                }
                refreshBtn.disabled = false;
                refreshBtn.textContent = '↻';
            })
            .catch(function(error) {
                console.error('Error:', error);
                alert('Failed to refresh status');
                refreshBtn.disabled = false;
                refreshBtn.textContent = '↻';
            });
        }
        
        function openAddModal() {
            document.getElementById('add-pnode-name').value = '';
            document.getElementById('add-pnode-ip').value = '';
            document.getElementById('addModal').style.display = 'block';
        }
        
        function closeAddModal() {
            document.getElementById('addModal').style.display = 'none';
        }
        
        function openEditModal(deviceId, currentName, currentIp) {
            document.getElementById('edit-device-id').value = deviceId;
            document.getElementById('edit-pnode-name').value = currentName;
            document.getElementById('edit-pnode-ip').value = currentIp;
            document.getElementById('editModal').style.display = 'block';
        }
        
        function closeEditModal() {
            document.getElementById('editModal').style.display = 'none';
        }
        
        function openDeleteModal(deviceId, deviceName) {
            document.getElementById('delete-device-id').value = deviceId;
            document.getElementById('delete-device-name').textContent = deviceName;
            document.getElementById('deleteModal').style.display = 'block';
        }
        
        function closeDeleteModal() {
            document.getElementById('deleteModal').style.display = 'none';
        }

        function openUpdateControllerModal(deviceId, deviceIp, deviceName) {
            window.pendingControllerUpdate = { deviceId: deviceId, deviceIp: deviceIp, deviceName: deviceName };
            document.getElementById('update-controller-device-name').textContent = deviceName;
            document.getElementById('update-controller-device-ip').textContent = deviceIp;
            document.getElementById('updateControllerModal').style.display = 'block';
        }
        
        function closeUpdateControllerModal() {
            document.getElementById('updateControllerModal').style.display = 'none';
            window.pendingControllerUpdate = null;
        }

        function openUpdatePodModal(deviceId, deviceIp, deviceName) {
            window.pendingPodUpdate = { deviceId: deviceId, deviceIp: deviceIp, deviceName: deviceName };
            document.getElementById('update-pod-device-name').textContent = deviceName;
            document.getElementById('update-pod-device-ip').textContent = deviceIp;
            document.getElementById('updatePodModal').style.display = 'block';
        }
        
        function closeUpdatePodModal() {
            document.getElementById('updatePodModal').style.display = 'none';
            window.pendingPodUpdate = null;
        }
        
        function submitAdd() {
            document.getElementById('addForm').submit();
        }
        
        function submitEdit() {
            document.getElementById('editForm').submit();
        }
        
        function submitDelete() {
            document.getElementById('deleteForm').submit();
        }
        
        function confirmUpdateController() {
            if (!window.pendingControllerUpdate) return;
            
            var updateData = window.pendingControllerUpdate;
            var deviceId = updateData.deviceId;
            var deviceIp = updateData.deviceIp;
            var deviceName = updateData.deviceName;
            
            closeUpdateControllerModal();
            
            console.log('User confirmed controller update for:', deviceName);
            
            var btn = document.querySelector('button[onclick*="openUpdateControllerModal(' + deviceId + '"]');
            if (!btn) {
                console.error('Could not find controller button for device', deviceId);
                alert('Error: Could not find update button');
                return;
            }
            
            var originalText = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Updating...';
            
            console.log('Sending controller update request...');
            
            fetch('device_update.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=update_controller&device_id=' + deviceId + '&device_ip=' + encodeURIComponent(deviceIp)
            })
            .then(function(response) {
                console.log('Controller update response received:', response.status);
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status + ': ' + response.statusText);
                }
                return response.json();
            })
            .then(function(data) {
                console.log('Controller update response data:', data);
                if (data.success) {
                    alert('✅ Controller update initiated successfully for ' + deviceName + '!\n\nResponse: ' + (data.message || 'Update started'));
                } else {
                    alert('❌ Controller update failed for ' + deviceName + '!\n\nError: ' + (data.error || 'Unknown error'));
                }
                btn.disabled = false;
                btn.textContent = originalText;
            })
            .catch(function(error) {
                console.error('Controller update error:', error);
                alert('❌ Controller update failed for ' + deviceName + '!\n\nNetwork error: ' + error.message);
                btn.disabled = false;
                btn.textContent = originalText;
            });
        }
        
        function confirmUpdatePod() {
            if (!window.pendingPodUpdate) return;
            
            var updateData = window.pendingPodUpdate;
            var deviceId = updateData.deviceId;
            var deviceIp = updateData.deviceIp;
            var deviceName = updateData.deviceName;
            
            closeUpdatePodModal();
            
            console.log('User confirmed pod update for:', deviceName);
            
            var btn = document.querySelector('button[onclick*="openUpdatePodModal(' + deviceId + '"]');
            if (!btn) {
                console.error('Could not find pod button for device', deviceId);
                alert('Error: Could not find update button');
                return;
            }
            
            var originalText = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Updating...';
            
            console.log('Sending pod update request...');
            
            fetch('device_update.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=update_pod&device_id=' + deviceId + '&device_ip=' + encodeURIComponent(deviceIp)
            })
            .then(function(response) {
                console.log('Pod update response received:', response.status);
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status + ': ' + response.statusText);
                }
                return response.json();
            })
            .then(function(data) {
                console.log('Pod update response data:', data);
                if (data.success) {
                    alert('✅ Pod update initiated successfully for ' + deviceName + '!\n\nResponse: ' + (data.message || 'Update started'));
                } else {
                    alert('❌ Pod update failed for ' + deviceName + '!\n\nError: ' + (data.error || 'Unknown error'));
                }
                btn.disabled = false;
                btn.textContent = originalText;
            })
            .catch(function(error) {
                console.error('Pod update error:', error);
                alert('❌ Pod update failed for ' + deviceName + '!\n\nNetwork error: ' + error.message);
                btn.disabled = false;
                btn.textContent = originalText;
            });
        }
        
        window.onclick = function(event) {
            var addModal = document.getElementById('addModal');
            var editModal = document.getElementById('editModal');
            var deleteModal = document.getElementById('deleteModal');
            var updateControllerModal = document.getElementById('updateControllerModal');
            var updatePodModal = document.getElementById('updatePodModal');
            
            if (event.target == addModal) {
                closeAddModal();
            }
            if (event.target == editModal) {
                closeEditModal();
            }
            if (event.target == deleteModal) {
                closeDeleteModal();
            }
            if (event.target == updateControllerModal) {
                closeUpdateControllerModal();
            }
            if (event.target == updatePodModal) {
                closeUpdatePodModal();
            }
        };
        
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeAddModal();
                closeEditModal();
                closeDeleteModal();
                closeUpdateControllerModal();
                closeUpdatePodModal();
            }
        });
    </script>
</body>
</html>                                </tr>
                                <tr>
                                    <td colspan="8">
                                        <details>
                                            <summary>Status Logs</summary>
                                            <div id="log-container-<?php echo $device['id']; ?>">
                                                <table class="status-log-table">
                                                    <thead>
                                                        <tr>
                                                            <th>Status</th>
                                                            <th>Check Time</th>
                                                            <th>Response</th>
                                                            <th>Health</th>
                                                            <th>Atlas</th>
                                                            <th>Services</th>
                                                            <th>System</th>
                                                            <th>Errors</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <?php if (empty($device['logs'])): ?>
                                                            <tr>
                                                                <td colspan="8">No status logs for this device.</td>
                                                            </tr>
                                                        <?php else: ?>
                                                            <?php foreach ($device['logs'] as $log): ?>
                                                                <tr>
                                                                    <td>
                                                                        <span class="<?php echo $log['status'] === 'Online' ? 'log-status-online' : ($log['status'] === 'Offline' ? 'log-status-offline' : 'log-status-error'); ?>">
                                                                            <?php echo htmlspecialchars($log['status']); ?>
                                                                        </span>
                                                                    </td>
                                                                    <td><?php echo htmlspecialchars($log['check_time']); ?></td>
                                                                    <td><?php echo $log['response_time'] ? round($log['response_time'] * 1000) . 'ms' : 'N/A'; ?></td>
                                                                    <td>
                                                                        <?php if ($log['health_status']): ?>
                                                                            <span class="log-health-<?php echo $log['health_status']; ?>"><?php echo htmlspecialchars($log['health_status']); ?></span>
                                                                        <?php else: ?>
                                                                            N/A
                                                                        <?php endif; ?>
                                                                    </td>
                                                                    <td>
                                                                        <?php if (isset($log['atlas_registered'])): ?>
                                                                            <span class="log-atlas-<?php echo $log['atlas_registered'] ? 'yes' : 'no'; ?>"><?php echo $log['atlas_registered'] ? 'Yes' : 'No'; ?></span>
                                                                        <?php else: ?>
                                                                            N/A
                                                                        <?php endif; ?>
                                                                    </td>
                                                                    <td>
                                                                        <?php 
                                                                        $services = [];
                                                                        if ($log['pod_status']) $services[] = 'Pod: <span class="log-service-' . $log['pod_status'] . '">' . htmlspecialchars($log['pod_status']) . '</span>';
                                                                        if ($log['xandminer_status']) $services[] = 'XM: <span class="log-service-' . $log['xandminer_status'] . '">' . htmlspecialchars($log['xandminer_status']) . '</span>';
                                                                        if ($log['xandminerd_status']) $services[] = 'XMD: <span class="log-service-' . $log['xandminerd_status'] . '">' . htmlspecialchars($log['xandminerd_status']) . '</span>';
                                                                        echo $services ? implode('<br>', $services) : 'N/A';
                                                                        ?>
                                                                    </td>
                                                                    <td>
                                                                        <span class="log-metrics">
                                                                        <?php 
                                                                        $metrics = [];
                                                                        if ($log['cpu_load_avg'] !== null) $metrics[] = 'CPU: ' . number_format($log['cpu_load_avg'], 2);
                                                                        if ($log['memory_percent'] !== null) $metrics[] = 'Mem: ' . number_format($log['memory_percent'], 1) . '%';
                                                                        if ($log['consecutive_failures'] > 0) $metrics[] = 'Fails: ' . $log['consecutive_failures'];
                                                                        echo $metrics ? implode('<br>', $metrics) : 'N/A';
                                                                        ?>
                                                                        </span>
                                                                    </td>
                                                                    <td>
                                                                        <?php if ($log['error_message']): ?>
                                                                            <span class="log-error" title="<?php echo htmlspecialchars($log['error_message']); ?>">
                                                                                <?php echo htmlspecialchars(strlen($log['error_message']) > 30 ? substr($log['error_message'], 0, 30) . '...' : $log['error_message']); ?>
                                                                            </span>
                                                                        <?php else: ?>
                                                                            None
                                                                        <?php endif; ?>
                                                                    </td>
                                                                </tr>
                                                            <?php endforeach; ?>
                                                        <?php endif; ?>
                                                    </tbody>
                                                </table>
                                            </div>
                                            <?php if ($device['total_logs'] > $limit): ?>
                                                <button type="button" class="action-btn-tiny action-more" id="more-items-<?php echo $device['id']; ?>" onclick="showMoreItems(<?php echo $device['id']; ?>)">More Items</button>
                                            <?php endif; ?>
                                            <div id="pagination-<?php echo $device['id']; ?>" class="pagination-buttons"></div>
                                        </details>
                                    </td>
                                <?php
// devices.php - Updated to show device status logs instead of user interactions
session_start();

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once 'db_connect.php';
require_once 'functions.php';

// Set reasonable execution limits
set_time_limit(30);
ini_set('max_execution_time', 30);

// CLI mock session for testing
if (PHP_SAPI === 'cli') {
    $_SESSION['user_id'] = 1;
    $_SESSION['username'] = 'test_user';
    $_SESSION['admin'] = 0;
    error_log("CLI mode: Mock session set");
}

// Check if PDO is initialized
if (!isset($pdo) || $pdo === null) {
    $error = "Database connection error. Please contact the administrator.";
    error_log("PDO object is null in devices.php");
    if (PHP_SAPI !== 'cli') {
        echo "<p class='error'>" . htmlspecialchars($error) . "</p>";
        exit();
    } else {
        echo $error . "\n";
        exit(1);
    }
}

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    if (PHP_SAPI !== 'cli') {
        header("Location: login.php");
        exit();
    } else {
        error_log("No user_id in session for CLI execution.");
        echo "Error: No user session available in CLI mode.\n";
        exit(1);
    }
}

// Fetch admin status
try {
    $stmt = $pdo->prepare("SELECT admin FROM users WHERE id = :user_id");
    $stmt->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) {
        $error = "User not found for ID: {$_SESSION['user_id']}";
        error_log($error);
        if (PHP_SAPI !== 'cli') {
            header("Location: login.php");
            exit();
        } else {
            echo "$error\n";
            exit(1);
        }
    }
    $_SESSION['admin'] = $user['admin'];
    error_log("Admin status fetched: admin={$_SESSION['admin']}");
} catch (PDOException $e) {
    $error = "Error fetching user details: " . $e->getMessage();
    error_log($error);
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'user_fetch_failed', $error);
}

// Fetch user's devices with latest status (FAST - no blocking operations!)
try {
    $stmt = $pdo->prepare("
        SELECT d.id, d.pnode_name, d.pnode_ip, d.registration_date 
        FROM devices d 
        WHERE d.username = :username OR :admin = 1 
        ORDER BY d.pnode_name ASC
    ");
    $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
    $stmt->bindValue(':admin', $_SESSION['admin'], PDO::PARAM_INT);
    $stmt->execute();
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
    error_log("Fetched " . count($devices) . " devices for user {$_SESSION['username']}");
    
    // Get latest statuses for all devices at once (super efficient!)
    $device_ids = array_column($devices, 'id');
    $cached_statuses = getLatestDeviceStatuses($pdo, $device_ids);
    
    // Add cached status and health data to each device
    $updated_devices = [];
    $summaries = [];
    $limit = 3;
    
    foreach ($devices as $device) {
        $device_id = $device['id'];
        $cached_status = $cached_statuses[$device_id] ?? [
            'status' => 'Not Initialized',
            'is_stale' => true,
            'error_message' => 'Device has not been checked yet'
        ];
        
        // Add status from cache
        $device['status'] = $cached_status['status'];
        $device['status_age'] = $cached_status['age_minutes'];
        $device['status_stale'] = $cached_status['is_stale'];
        $device['last_check'] = $cached_status['check_time'];
        $device['response_time'] = $cached_status['response_time'];
        $device['consecutive_failures'] = $cached_status['consecutive_failures'];
        $device['health_status'] = $cached_status['health_status'];
        
        // Determine overall status (connectivity + health)
        $overall_status = 'Unknown';
        if ($device['status'] === 'Online') {
            if ($device['health_status'] === 'pass') {
                $overall_status = 'Healthy';
            } elseif ($device['health_status'] === 'fail') {
                $overall_status = 'Online (Issues)';
            } else {
                $overall_status = 'Online';
            }
        } elseif ($device['status'] === 'Offline') {
            $overall_status = 'Offline';
        } else {
            $overall_status = $device['status'];
        }
        $device['overall_status'] = $overall_status;
        
        // Parse health data from cached data
        $summaries[$device_id] = parseCachedDeviceHealth($cached_status);
        
        // Fetch initial device status logs (instead of user interactions)
        $sql = "
            SELECT status, check_time, response_time, error_message, health_status,
                   atlas_registered, pod_status, xandminer_status, xandminerd_status,
                   cpu_load_avg, memory_percent, consecutive_failures
            FROM device_status_log 
            WHERE device_id = :device_id
            ORDER BY check_time DESC 
            LIMIT :limit
        ";
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
        $stmt->bindValue(':limit', (int)$limit, PDO::PARAM_INT);
        $stmt->execute();
        $device['logs'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Count total device status logs
        $sql = "
            SELECT COUNT(*) 
            FROM device_status_log 
            WHERE device_id = :device_id
        ";
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
        $stmt->execute();
        $device['total_logs'] = $stmt->fetchColumn();
        
        $updated_devices[] = $device;
    }
    $devices = $updated_devices;
    
} catch (PDOException $e) {
    $error = "Error fetching devices or logs: " . $e->getMessage();
    error_log("PDOException in device/log fetch: " . $e->getMessage());
    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_fetch_failed', $error);
}

// Handle add device
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'add') {
    $pnode_name = trim($_POST['pnode_name']);
    $pnode_ip = trim($_POST['pnode_ip']);
    
    if (empty($pnode_name) || empty($pnode_ip)) {
        $error = "Please fill in all fields.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', 'Empty fields');
    } elseif (strlen($pnode_name) > 100) {
        $error = "Node name must be 100 characters or less.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', 'Invalid node name length');
    } elseif (!filter_var($pnode_ip, FILTER_VALIDATE_IP)) {
        $error = "Invalid IP address.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', 'Invalid IP address');
    } else {
        try {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE username = :username AND pnode_name = :pnode_name");
            $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
            $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
            $stmt->execute();
            if ($stmt->fetchColumn() > 0) {
                $error = "Device name already registered.";
                logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', 'Duplicate device name');
            } else {
                // Add device (no seeding required)
                $stmt = $pdo->prepare("INSERT INTO devices (username, pnode_name, pnode_ip, registration_date) VALUES (:username, :pnode_name, :pnode_ip, NOW())");
                $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
                $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
                $stmt->bindValue(':pnode_ip', $pnode_ip, PDO::PARAM_STR);
                $stmt->execute();
                
                // Get the new device ID (no seeding required - system handles gracefully)
                $new_device_id = $pdo->lastInsertId();
                
                logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_success', "Device: $pnode_name, IP: $pnode_ip");
                if (PHP_SAPI !== 'cli') {
                    header("Location: devices.php");
                    exit();
                } else {
                    echo "Device added successfully: $pnode_name, $pnode_ip\n";
                }
            }
        } catch (PDOException $e) {
            $error = "Error adding device: " . $e->getMessage();
            error_log($error);
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_register_failed', $error);
        }
    }
}

// Handle edit device
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'edit') {
    $device_id = $_POST['device_id'];
    $pnode_name = trim($_POST['pnode_name']);
    $pnode_ip = trim($_POST['pnode_ip']);
    
    if (empty($pnode_name) || empty($pnode_ip)) {
        $error = "Please fill in all fields.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', 'Empty fields');
    } elseif (strlen($pnode_name) > 100) {
        $error = "Node name must be 100 characters or less.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', 'Invalid node name length');
    } elseif (!filter_var($pnode_ip, FILTER_VALIDATE_IP)) {
        $error = "Invalid IP address.";
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', 'Invalid IP address');
    } else {
        try {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE id = :device_id AND (username = :username OR :admin = 1)");
            $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
            $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
            $stmt->bindValue(':admin', $_SESSION['admin'], PDO::PARAM_INT);
            $stmt->execute();
            if ($stmt->fetchColumn() == 0) {
                $error = "Device not found or not authorized.";
                logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', 'Unauthorized device access');
            } else {
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE username = :username AND pnode_name = :pnode_name AND id != :device_id");
                $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
                $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
                $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
                $stmt->execute();
                if ($stmt->fetchColumn() > 0) {
                    $error = "Device name already registered.";
                    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', 'Duplicate device name');
                } else {
                    $stmt = $pdo->prepare("UPDATE devices SET pnode_name = :pnode_name, pnode_ip = :pnode_ip WHERE id = :device_id AND (username = :username OR :admin = 1)");
                    $stmt->bindValue(':pnode_name', $pnode_name, PDO::PARAM_STR);
                    $stmt->bindValue(':pnode_ip', $pnode_ip, PDO::PARAM_STR);
                    $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
                    $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
                    $stmt->bindValue(':admin', $_SESSION['admin'], PDO::PARAM_INT);
                    $stmt->execute();
                    
                    logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_success', "Device ID: $device_id, New Name: $pnode_name, New IP: $pnode_ip");
                    if (PHP_SAPI !== 'cli') {
                        header("Location: devices.php");
                        exit();
                    } else {
                        echo "Device edited successfully: ID=$device_id, $pnode_name, $pnode_ip\n";
                    }
                }
            }
        } catch (PDOException $e) {
            $error = "Error editing device: " . $e->getMessage();
            error_log($error);
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_edit_failed', $error);
        }
    }
}

// Handle delete device
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['action']) && $_POST['action'] == 'delete') {
    $device_id = $_POST['device_id'];
    try {
        $stmt = $pdo->prepare("SELECT pnode_name, pnode_ip FROM devices WHERE id = :device_id AND (username = :username OR :admin = 1)");
        $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
        $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
        $stmt->bindValue(':admin', $_SESSION['admin'], PDO::PARAM_INT);
        $stmt->execute();
        $device = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($device) {
            // Delete device (cascade will handle device_status_log)
            $stmt = $pdo->prepare("DELETE FROM devices WHERE id = :device_id AND (username = :username OR :admin = 1)");
            $stmt->bindValue(':device_id', $device_id, PDO::PARAM_INT);
            $stmt->bindValue(':username', $_SESSION['username'], PDO::PARAM_STR);
            $stmt->bindValue(':admin', $_SESSION['admin'], PDO::PARAM_INT);
            $stmt->execute();
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_delete_success', "Device: {$device['pnode_name']}, IP: {$device['pnode_ip']}");
            if (PHP_SAPI !== 'cli') {
                header("Location: devices.php");
                exit();
            } else {
                echo "Device deleted successfully: {$device['pnode_name']}, {$device['pnode_ip']}\n";
            }
        } else {
            $error = "Device not found or not authorized.";
            logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_delete_failed', 'Unauthorized device access');
        }
    } catch (PDOException $e) {
        $error = "Error deleting device: " . $e->getMessage();
        error_log($error);
        logInteraction($pdo, $_SESSION['user_id'], $_SESSION['username'], 'device_delete_failed', $error);
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Devices</title>
    <link rel="icon" type="image/x-icon" href="images/favicon.ico">
    <link rel="icon" type="image/png" sizes="32x32" href="images/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="images/favicon-16x16.png">
    <link rel="stylesheet" href="style.css">
    <style>
        .summary-container { margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; background: #f9f9f9; }
        .action-btn-tiny { padding: 5px 10px; margin-left: 10px; cursor: pointer; }
        .error { color: red; }
        .status-age { font-size: 10px; color: #666; }
        .status-stale { color: #ff6600; }
        .status-fresh { color: #006600; }
        .refresh-btn { 
            background-color: #17a2b8; 
            color: white; 
            border: none; 
            padding: 1px 4px; 
            font-size: 9px; 
            border-radius: 2px; 
            cursor: pointer; 
            margin-left: 3px;
            width: 14px;
            height: 14px;
            line-height: 1;
        }
        .refresh-btn:hover { background-color: #138496; }
        .device-details { font-size: 11px; color: #666; margin-top: 3px; }
        .status-not-initialized { background-color: #6c757d; }
        .status-healthy { background-color: #28a745; }
        .status-online-issues { background-color: #ffc107; color: #212529; }
        .last-check-col { font-size: 11px; color: #666; }
        .never-checked { font-style: italic; color: #999; }
        .status-log-table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 11px; }
        .status-log-table th, .status-log-table td { 
            border: 1px solid #ddd; 
            padding: 4px; 
            text-align: left; 
            font-size: 11px; 
            vertical-align: top;
        }
        .status-log-table th { background-color: #f8f9fa; font-weight: bold; }
        .log-status-online { color: #28a745; font-weight: bold; }
        .log-status-offline { color: #dc3545; font-weight: bold; }
        .log-status-error { color: #ffc107; font-weight: bold; }
        .log-health-pass { color: #28a745; }
        .log-health-fail { color: #dc3545; }
        .log-atlas-yes { color: #28a745; }
        .log-atlas-no { color: #dc3545; }
        .log-service-active { color: #28a745; }
        .log-service-inactive { color: #dc3545; }
        .log-metrics { font-size: 10px; color: #666; }
        .log-error { color: #dc3545; font-size: 10px; }
        
        /* Update buttons styling */
        .update-btn-controller { 
            background-color: #fd7e14; 
            color: white; 
            border: none; 
            padding: 5px 10px; 
            font-size: 10px; 
            border-radius: 3px; 
            cursor: pointer; 
            margin-left: 5px;
            margin-top: 3px;
        }
        .update-btn-controller:hover { background-color: #e66a00; }
        .update-btn-controller:disabled { background-color: #ccc; cursor: not-allowed; }
        
        .update-btn-pod { 
            background-color: #6f42c1; 
            color: white; 
            border: none; 
            padding: 5px 10px; 
            font-size: 10px; 
            border-radius: 3px; 
            cursor: pointer; 
            margin-left: 5px;
            margin-top: 3px;
        }
        .update-btn-pod:hover { background-color: #59359a; }
        .update-btn-pod:disabled { background-color: #ccc; cursor: not-allowed; }
        
        /* Modal styling */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        .modal-content {
            background-color: #fefefe;
            margin: 15% auto;
            padding: 20px;
            border: 1px solid #888;
            border-radius: 5px;
            width: 400px;
            max-width: 90%;
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .close {
            color: #aaa;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        .close:hover {
            color: black;
        }
        .modal-form-group {
            margin-bottom: 15px;
        }
        .modal-form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        .modal-form-group input {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 3px;
            box-sizing: border-box;
        }
        .modal-buttons {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }
        .modal-btn {
            padding: 8px 16px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        .modal-btn-primary {
            background-color: #007bff;
            color: white;
        }
        .modal-btn-primary:hover {
            background-color: #0056b3;
        }
        .modal-btn-secondary {
            background-color: #6c757d;
            color: white;
        }
        .modal-btn-secondary:hover {
            background-color: #545b62;
        }
        .modal-btn-danger {
            background-color: #dc3545;
            color: white;
        }
        .modal-btn-danger:hover {
            background-color: #c82333;
        }
        .action-btn {
            background-color: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .action-btn:hover {
            background-color: #0056b3;
        }
        .version-info {
            font-size: 10px; 
            line-height: 1.3; 
            color: #666;
        }
        .version-value {
            font-family: 'Courier New', monospace;
            color: #333;
            font-weight: 500;
        }
        .dashboard-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .summary-card {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            text-align: center;
        }
        .summary-card h4 {
            margin: 0 0 10px 0;
            color: #495057;
        }
        .summary-number {
            font-size: 24px;
            font-weight: bold;
            margin: 5px 0;
        }
        .summary-online { color: #28a745; }
        .summary-offline { color: #dc3545; }
        .summary-total { color: #007bff; }
        .summary-issues { color: #ffc107; }
    </style>
</head>
<body>
    <div class="console-container">
        <div class="top-bar">
            <h1>ChillXand - pNode Management Console</h1>
            <div class="user-info">
                <span>Welcome, <?php echo htmlspecialchars($_SESSION['username'] ?? 'Guest'); ?></span>
                <a href="logout.php" class="logout-btn">Logout</a>
            </div>
        </div>
        <div class="main-content">
            <div class="menu-column">
                <img src="images/logo.png">
                <ul>
                    <li><button class="menu-button" onclick="window.location.href='dashboard.php'">Dashboard</button></li>
                    <li><button class="menu-button active" onclick="window.location.href='devices.php'">Manage Devices</button></li>
                    <li><button class="menu-button" onclick="window.location.href='device_logs.php'">Device Logs</button></li>
                    <?php if ($_SESSION['admin'] ?? false): ?>
                        <li class="admin-section">
                            <strong>Admin</strong>
                            <ul>
                                <li><button class="menu-button admin-button" onclick="window.location.href='admin_users.php'">Users</button></li>
                                <li><button class="menu-button admin-button" onclick="window.location.href='admin_devices.php'">Devices</button></li>
                            </ul>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
            <div class="info-panel">
                <h2>Manage Devices</h2>
                <?php if (isset($error)): ?>
                    <p class="error"><?php echo htmlspecialchars($error); ?></p>
                <?php endif; ?>
                
                <div style="margin-bottom: 20px;">
                    <button type="button" class="action-btn" id="add-device-btn" onclick="openAddModal()">Add New Device</button>
                </div>

                <!-- Device Summary Cards -->
                <?php if (!empty($devices)): ?>
                    <?php
                    $total_devices = count($devices);
                    $online_devices = count(array_filter($devices, function($d) { return $d['status'] === 'Online'; }));
                    $offline_devices = count(array_filter($devices, function($d) { return $d['status'] === 'Offline'; }));
                    $healthy_devices = count(array_filter($devices, function($d) { return $d['overall_status'] === 'Healthy'; }));
                    $issues_devices = count(array_filter($devices, function($d) { return $d['overall_status'] === 'Online (Issues)'; }));
                    ?>
                    <div class="dashboard-summary">
                        <div class="summary-card">
                            <h4>Total Devices</h4>
                            <div class="summary-number summary-total"><?php echo $total_devices; ?></div>
                        </div>
                        <div class="summary-card">
                            <h4>Online</h4>
                            <div class="summary-number summary-online"><?php echo $online_devices; ?></div>
                        </div>
                        <div class="summary-card">
                            <h4>Healthy</h4>
                            <div class="summary-number summary-online"><?php echo $healthy_devices; ?></div>
                        </div>
                        <div class="summary-card">
                            <h4>With Issues</h4>
                            <div class="summary-number summary-issues"><?php echo $issues_devices; ?></div>
                        </div>
                        <div class="summary-card">
                            <h4>Offline</h4>
                            <div class="summary-number summary-offline"><?php echo $offline_devices; ?></div>
                        </div>
                    </div>
                <?php endif; ?>

                <h3>Your Devices</h3>
                <?php if (empty($devices)): ?>
                    <p>No devices registered.</p>
                <?php else: ?>
                    <table class="device-table">
                        <thead>
                            <tr>
                                <th>Node Name</th>
                                <th>IP Address</th>
                                <th>Registration Date</th>
                                <th>Connectivity</th>
                                <th>Health Status</th>
                                <th>Versions</th>
                                <th>Last Checked</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($devices as $device): ?>
                                <tr>
                                    <td><a href="device_details.php?device_id=<?php echo $device['id']; ?>"><?php echo htmlspecialchars($device['pnode_name']); ?></a></td>
                                    <td><?php echo htmlspecialchars($device['pnode_ip']); ?></td>
                                    <td><?php echo htmlspecialchars($device['registration_date']); ?></td>
                                    <td id="status-<?php echo $device['id']; ?>">
                                        <span class="status-btn status-<?php echo strtolower(str_replace(' ', '-', $device['status'])); ?>">
                                            <?php echo htmlspecialchars($device['status']); ?>
                                        </span>
                                        <button class="refresh-btn" id="refresh-<?php echo $device['id']; ?>" onclick="refreshDeviceStatus(<?php echo $device['id']; ?>)" title="Refresh status">↻</button>
                                        <div class="status-age <?php echo $device['status_stale'] ? 'status-stale' : 'status-fresh'; ?>">
                                            <?php if ($device['last_check']): ?>
                                                <?php echo $device['status_age'] ? round($device['status_age']) . 'm ago' : 'Just now'; ?>
                                            <?php else: ?>
                                                Never checked
                                            <?php endif; ?>
                                        </div>
                                        <?php if ($device['response_time']): ?>
                                            <div class="device-details">Response: <?php echo round($device['response_time'] * 1000, 1); ?>ms</div>
                                        <?php endif; ?>
                                        <?php if ($device['consecutive_failures'] > 0): ?>
                                            <div class="device-details" style="color: #dc3545;">Failures: <?php echo $device['consecutive_failures']; ?></div>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($device['status'] === 'Not Initialized'): ?>
                                            <span class="status-btn status-not-initialized">Not Initialized</span>
                                        <?php else: ?>
                                            <div style="font-size: 10px; line-height: 1.3;">
                                                <div><strong>Health:</strong> 
                                                    <span class="status-btn status-<?php echo $summaries[$device['id']]['health_status'] == 'pass' ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
                                                        <?php echo ucfirst($summaries[$device['id']]['health_status'] ?? 'unknown'); ?>
                                                    </span>
                                                </div>
                                                <div><strong>Atlas:</strong> 
                                                    <span class="status-btn status-<?php echo $summaries[$device['id']]['atlas_registered'] ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
                                                        <?php echo $summaries[$device['id']]['atlas_registered'] ? 'Yes' : 'No'; ?>
                                                    </span>
                                                </div>
                                                <div><strong>Pod:</strong> 
                                                    <span class="status-btn status-<?php echo $summaries[$device['id']]['pod_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
                                                        <?php echo ucfirst($summaries[$device['id']]['pod_status'] ?? 'unknown'); ?>
                                                    </span>
                                                </div>
                                                <div><strong>XandMiner:</strong> 
                                                    <span class="status-btn status-<?php echo $summaries[$device['id']]['xandminer_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
                                                        <?php echo ucfirst($summaries[$device['id']]['xandminer_status'] ?? 'unknown'); ?>
                                                    </span>
                                                </div>
                                                <div><strong>XandMinerD:</strong> 
                                                    <span class="status-btn status-<?php echo $summaries[$device['id']]['xandminerd_status'] == 'active' ? 'online' : 'offline'; ?>" style="padding: 1px 4px; font-size: 9px;">
                                                        <?php echo ucfirst($summaries[$device['id']]['xandminerd_status'] ?? 'unknown'); ?>
                                                    </span>
                                                </div>
                                            </div>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($device['status'] === 'Not Initialized'): ?>
                                            <span class="status-btn status-not-initialized">Not Initialized</span>
                                        <?php else: ?>
                                            <div class="version-info">
                                                <div><strong>Controller:</strong> 
                                                    <span class="version-value">
                                                        <?php echo htmlspecialchars($summaries[$device['id']]['chillxand_version'] ?? 'N/A'); ?>
                                                    </span>
                                                </div>
                                                <div><strong>Node:</strong> 
                                                    <span class="version-value">
                                                        <?php echo htmlspecialchars($summaries[$device['id']]['node_version'] ?? 'N/A'); ?>
                                                    </span>
                                                </div>
                                                <div><strong>Pod:</strong> 
                                                    <span class="version-value">
                                                        <?php 
                                                        $pod_version = 'N/A';
                                                        if (!empty($summaries[$device['id']]['pod_status']) && $summaries[$device['id']]['pod_status'] === 'active') {
                                                            $pod_version = 'Active';
                                                        }
                                                        echo htmlspecialchars($pod_version);
                                                        ?>
                                                    </span>
                                                </div>
                                                <div><strong>XandMiner:</strong> 
                                                    <span class="version-value">
                                                        <?php 
                                                        $xm_version = 'N/A';
                                                        if (!empty($summaries[$device['id']]['xandminer_status']) && $summaries[$device['id']]['xandminer_status'] === 'active') {
                                                            $xm_version = 'Active';
                                                        }
                                                        echo htmlspecialchars($xm_version);
                                                        ?>
                                                    </span>
                                                </div>
                                                <div><strong>XandMinerD:</strong> 
                                                    <span class="version-value">
                                                        <?php 
                                                        $xmd_version = 'N/A';
                                                        if (!empty($summaries[$device['id']]['xandminerd_status']) && $summaries[$device['id']]['xandminerd_status'] === 'active') {
                                                            $xmd_version = 'Active';
                                                        }
                                                        echo htmlspecialchars($xmd_version);
                                                        ?>
                                                    </span>
                                                </div>
                                            </div>
                                        <?php endif; ?>
                                    </td>
                                    <td class="last-check-col" id="lastcheck-<?php echo $device['id']; ?>">
                                        <?php if ($device['last_check']): ?>
                                            <div class="<?php echo $device['status_stale'] ? 'status-stale' : 'status-fresh'; ?>">
                                                <?php echo $device['status_age'] ? round($device['status_age']) . ' min ago' : 'Just now'; ?>
                                            </div>
                                            <div style="font-size: 10px; color: #999;">
                                                <?php echo date('M j, H:i', strtotime($device['last_check'])); ?>
                                            </div>
                                        <?php else: ?>
                                            <div class="never-checked">Never checked</div>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <button type="button" class="action-btn-tiny action-edit" 
                                                onclick="openEditModal(<?php echo $device['id']; ?>, '<?php echo htmlspecialchars($device['pnode_name'], ENT_QUOTES); ?>', '<?php echo htmlspecialchars($device['pnode_ip']); ?>')">Edit</button>
                                        <button type="button" class="action-btn-tiny action-delete" 
                                                onclick="openDeleteModal(<?php echo $device['id']; ?>, '<?php echo htmlspecialchars($device['pnode_name'], ENT_QUOTES); ?>')">Delete</button>
                                        <br>
                                        <button type="button" class="update-btn-controller" 
                                                onclick="openUpdateControllerModal(<?php echo $device['id']; ?>, '<?php echo htmlspecialchars($device['pnode_ip']); ?>', '<?php echo htmlspecialchars($device['pnode_name'], ENT_QUOTES); ?>')">
                                            Update Controller
                                        </button>
                                        <button type="button" class="update-btn-pod" 
                                                onclick="openUpdatePodModal(<?php echo $device['id']; ?>, '<?php echo htmlspecialchars($device['pnode_ip']); ?>', '<?php echo htmlspecialchars($device['pnode_name'], ENT_QUOTES); ?>')">
                                            Update Pod
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
                
                <div style="margin-top: 20px; padding: 10px; background-color: #e9ecef; border-radius: 4px;">
                    <h4>Background Health Monitoring</h4>
                    <p><small>Device health status is automatically checked every 2 minutes by a background process. 
                    Use the refresh button (↻) next to each device for immediate status updates. The status logs show 
                    device connectivity checks, response times, and health status. Update buttons allow you to trigger 
                    controller or pod updates on the remote devices.</small></p>
                </div>
            </div>
        </div>
    </div>

    <!-- Update Controller Modal -->
    <div id="updateControllerModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>⚠️ Update Controller</h3>
                <span class="close" onclick="closeUpdateControllerModal()">&times;</span>
            </div>
            <div>
                <p><strong>Are you sure you want to update the controller for "<span id="update-controller-device-name"></span>"?</strong></p>
                <p>Device IP: <strong><span id="update-controller-device-ip"></span></strong></p>
                <p style="color: #dc3545; font-weight: bold;">⚠️ WARNING: The device may be temporarily unavailable during the update process!</p>
                <p>This will trigger an update process on the remote device.</p>
                <div class="modal-buttons">
                    <button type="button" class="modal-btn modal-btn-secondary" onclick="closeUpdateControllerModal()">Cancel</button>
                    <button type="button" class="modal-btn modal-btn-danger" onclick="confirmUpdateController()">Yes, Update Controller</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Update Pod Modal -->
    <div id="updatePodModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>⚠️ Update Pod</h3>
                <span class="close" onclick="closeUpdatePodModal()">&times;</span>
            </div>
            <div>
                <p><strong>Are you sure you want to update the pod for "<span id="update-pod-device-name"></span>"?</strong></p>
                <p>Device IP: <strong><span id="update-pod-device-ip"></span></strong></p>
                <p style="color: #dc3545; font-weight: bold;">⚠️ WARNING: The device may be temporarily unavailable during the update process!</p>
                <p>This will trigger an update process on the remote device.</p>
                <div class="modal-buttons">
                    <button type="button" class="modal-btn modal-btn-secondary" onclick="closeUpdatePodModal()">Cancel</button>
                    <button type="button" class="modal-btn modal-btn-danger" onclick="confirmUpdatePod()">Yes, Update Pod</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Add Device Modal -->
    <div id="addModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Add New Device</h3>
                <span class="close" onclick="closeAddModal()">&times;</span>
            </div>
            <form id="addForm" method="POST" action="">
                <input type="hidden" name="action" value="add">
                <div class="modal-form-group">
                    <label for="add-pnode-name">Node Name:</label>
                    <input type="text" id="add-pnode-name" name="pnode_name" required>
                </div>
                <div class="modal-form-group">
                    <label for="add-pnode-ip">IP Address:</label>
                    <input type="text" id="add-pnode-ip" name="pnode_ip" required>
                </div>
                <div class="modal-buttons">
                    <button type="button" class="modal-btn modal-btn-secondary" onclick="closeAddModal()">Cancel</button>
                    <button type="button" class="modal-btn modal-btn-primary" onclick="submitAdd()">Add Device</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Edit Device Modal -->
    <div id="editModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Edit Device</h3>
                <span class="close" onclick="closeEditModal()">&times;</span>
            </div>
            <form id="editForm" method="POST" action="">
                <input type="hidden" name="action" value="edit">
                <input type="hidden" id="edit-device-id" name="device_id">
                <div class="modal-form-group">
                    <label for="edit-pnode-name">Node Name:</label>
                    <input type="text" id="edit-pnode-name" name="pnode_name" required>
                </div>
                <div class="modal-form-group">
                    <label for="edit-pnode-ip">IP Address:</label>
                    <input type="text" id="edit-pnode-ip" name="pnode_ip" required>
                </div>
                <div class="modal-buttons">
                    <button type="button" class="modal-btn modal-btn-secondary" onclick="closeEditModal()">Cancel</button>
                    <button type="button" class="modal-btn modal-btn-primary" onclick="submitEdit()">Save Changes</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Delete Device Modal -->
    <div id="deleteModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Delete Device</h3>
                <span class="close" onclick="closeDeleteModal()">&times;</span>
            </div>
            <form id="deleteForm" method="POST" action="">
                <input type="hidden" name="action" value="delete">
                <input type="hidden" id="delete-device-id" name="device_id">
                <p><strong>Are you sure you want to delete the device "<span id="delete-device-name"></span>"?</strong></p>
                <p style="color: #dc3545; font-weight: bold;">⚠️ This has dire results and cannot be undone!</p>
                <p>This will permanently remove the device and all its associated data from the system.</p>
                <div class="modal-buttons">
                    <button type="button" class="modal-btn modal-btn-secondary" onclick="closeDeleteModal()">Cancel</button>
                    <button type="button" class="modal-btn modal-btn-danger" onclick="submitDelete()">Delete Device</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        // Wait for DOM to be fully loaded before attaching event listeners
        document.addEventListener('DOMContentLoaded', function() {
            console.log('DOM loaded, initializing button handlers...');
            
            // Handle update controller buttons
            document.querySelectorAll('.update-btn-controller').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    const deviceId = this.getAttribute('data-device-id');
                    const deviceIp = this.getAttribute('data-device-ip');
                    const deviceName = this.getAttribute('data-device-name');
                    console.log('Controller update clicked:', deviceId, deviceIp, deviceName);
                    updateController(deviceId, deviceIp, deviceName);
                });
            });
            
            // Handle update pod buttons
            document.querySelectorAll('.update-btn-pod').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    const deviceId = this.getAttribute('data-device-id');
                    const deviceIp = this.getAttribute('data-device-ip');
                    const deviceName = this.getAttribute('data-device-name');
                    console.log('Pod update clicked:', deviceId, deviceIp, deviceName);
                    updatePod(deviceId, deviceIp, deviceName);
                });
            });
            
            console.log('Button handlers initialized successfully');
        });
        
        function refreshDeviceStatus(deviceId) {
            const statusElement = document.querySelector(`#status-${deviceId}`);
            const refreshBtn = document.querySelector(`#refresh-${deviceId}`);
            const lastCheckElement = document.querySelector(`#lastcheck-${deviceId}`);
            
            refreshBtn.disabled = true;
            refreshBtn.textContent = '⟳';
            
            fetch('manual_device_check.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `device_id=${deviceId}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert('Error: ' + data.error);
                } else {
                    let overallStatus = 'Unknown';
                    let statusClass = 'unknown';
                    
                    if (data.status === 'Online') {
                        statusClass = 'online';
                        overallStatus = data.status;
                    } else if (data.status === 'Offline') {
                        overallStatus = 'Offline';
                        statusClass = 'offline';
                    } else {
                        overallStatus = data.status;
                        statusClass = data.status.toLowerCase().replace(' ', '-');
                    }
                    
                    statusElement.innerHTML = `
                        <span class="status-btn status-${statusClass}">${overallStatus}</span>
                        <button class="refresh-btn" id="refresh-${deviceId}" onclick="refreshDeviceStatus(${deviceId})" title="Refresh status">↻</button>
                        <div class="status-age status-fresh">Just checked</div>
                        <div class="device-details">Response: ${data.response_time}ms</div>
                        ${data.consecutive_failures > 0 ? `<div class="device-details" style="color: #dc3545;">Failures: ${data.consecutive_failures}</div>` : ''}
                    `;
                    
                    const healthElement = statusElement.parentNode.nextElementSibling;
                    if (data.status === 'Online' && data.health_status) {
                        const healthClass = data.health_status === 'pass' ? 'online' : 'offline';
                        healthElement.innerHTML = `<span class="status-btn status-${healthClass}">${data.health_status.charAt(0).toUpperCase() + data.health_status.slice(1)}</span>`;
                    } else if (data.status === 'Not Initialized') {
                        healthElement.innerHTML = `<span class="status-btn status-not-initialized">Not Initialized</span>`;
                    } else {
                        healthElement.innerHTML = `<span class="status-btn status-not-initialized">Not Initialized</span>`;
                    }
                    
                    lastCheckElement.innerHTML = `
                        <div class="status-fresh">Just now</div>
                        <div style="font-size: 10px;">${data.timestamp}</div>
                    `;
                }
                refreshBtn.disabled = false;
                refreshBtn.textContent = '↻';
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Failed to refresh status');
                refreshBtn.disabled = false;
                refreshBtn.textContent = '↻';
            });
        }
        
        // Modal functions - using exact same pattern as delete
        function openAddModal() {
            document.getElementById('add-pnode-name').value = '';
            document.getElementById('add-pnode-ip').value = '';
            document.getElementById('addModal').style.display = 'block';
        }
        
        function closeAddModal() {
            document.getElementById('addModal').style.display = 'none';
        }
        
        function openEditModal(deviceId, currentName, currentIp) {
            document.getElementById('edit-device-id').value = deviceId;
            document.getElementById('edit-pnode-name').value = currentName;
            document.getElementById('edit-pnode-ip').value = currentIp;
            document.getElementById('editModal').style.display = 'block';
        }
        
        function closeEditModal() {
            document.getElementById('editModal').style.display = 'none';
        }
        
        function openDeleteModal(deviceId, deviceName) {
            document.getElementById('delete-device-id').value = deviceId;
            document.getElementById('delete-device-name').textContent = deviceName;
            document.getElementById('deleteModal').style.display = 'block';
        }
        
        function closeDeleteModal() {
            document.getElementById('deleteModal').style.display = 'none';
        }

        // Update controller modal - same pattern as delete
        function openUpdateControllerModal(deviceId, deviceIp, deviceName) {
            window.pendingControllerUpdate = { deviceId, deviceIp, deviceName };
            document.getElementById('update-controller-device-name').textContent = deviceName;
            document.getElementById('update-controller-device-ip').textContent = deviceIp;
            document.getElementById('updateControllerModal').style.display = 'block';
        }
        
        function closeUpdateControllerModal() {
            document.getElementById('updateControllerModal').style.display = 'none';
            window.pendingControllerUpdate = null;
        }

        // Update pod modal - same pattern as delete
        function openUpdatePodModal(deviceId, deviceIp, deviceName) {
            window.pendingPodUpdate = { deviceId, deviceIp, deviceName };
            document.getElementById('update-pod-device-name').textContent = deviceName;
            document.getElementById('update-pod-device-ip').textContent = deviceIp;
            document.getElementById('updatePodModal').style.display = 'block';
        }
        
        function closeUpdatePodModal() {
            document.getElementById('updatePodModal').style.display = 'none';
            window.pendingPodUpdate = null;
        }
        
        function submitAdd() {
            document.getElementById('addForm').submit();
        }
        
        function submitEdit() {
            document.getElementById('editForm').submit();
        }
        
        function submitDelete() {
            document.getElementById('deleteForm').submit();
        }
        
        // Confirm update functions - same pattern as delete
        function confirmUpdateController() {
            if (!window.pendingControllerUpdate) return;
            
            const { deviceId, deviceIp, deviceName } = window.pendingControllerUpdate;
            closeUpdateControllerModal();
            
            console.log('User confirmed controller update for:', deviceName);
            
            const btn = document.querySelector(`button[onclick*="openUpdateControllerModal(${deviceId}"]`);
            if (!btn) {
                console.error('Could not find controller button for device', deviceId);
                alert('Error: Could not find update button');
                return;
            }
            
            const originalText = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Updating...';
            
            console.log('Sending controller update request...');
            
            fetch('device_update.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=update_controller&device_id=${deviceId}&device_ip=${encodeURIComponent(deviceIp)}`
            })
            .then(response => {
                console.log('Controller update response received:', response.status);
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return response.json();
            })
            .then(data => {
                console.log('Controller update response data:', data);
                if (data.success) {
                    alert(`✅ Controller update initiated successfully for ${deviceName}!\n\nResponse: ${data.message || 'Update started'}`);
                } else {
                    alert(`❌ Controller update failed for ${deviceName}!\n\nError: ${data.error || 'Unknown error'}`);
                }
                btn.disabled = false;
                btn.textContent = originalText;
            })
            .catch(error => {
                console.error('Controller update error:', error);
                alert(`❌ Controller update failed for ${deviceName}!\n\nNetwork error: ${error.message}`);
                btn.disabled = false;
                btn.textContent = originalText;
            });
        }
        
        function confirmUpdatePod() {
            if (!window.pendingPodUpdate) return;
            
            const { deviceId, deviceIp, deviceName } = window.pendingPodUpdate;
            closeUpdatePodModal();
            
            console.log('User confirmed pod update for:', deviceName);
            
            const btn = document.querySelector(`button[onclick*="openUpdatePodModal(${deviceId}"]`);
            if (!btn) {
                console.error('Could not find pod button for device', deviceId);
                alert('Error: Could not find update button');
                return;
            }
            
            const originalText = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Updating...';
            
            console.log('Sending pod update request...');
            
            fetch('device_update.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=update_pod&device_id=${deviceId}&device_ip=${encodeURIComponent(deviceIp)}`
            })
            .then(response => {
                console.log('Pod update response received:', response.status);
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return response.json();
            })
            .then(data => {
                console.log('Pod update response data:', data);
                if (data.success) {
                    alert(`✅ Pod update initiated successfully for ${deviceName}!\n\nResponse: ${data.message || 'Update started'}`);
                } else {
                    alert(`❌ Pod update failed for ${deviceName}!\n\nError: ${data.error || 'Unknown error'}`);
                }
                btn.disabled = false;
                btn.textContent = originalText;
            })
            .catch(error => {
                console.error('Pod update error:', error);
                alert(`❌ Pod update failed for ${deviceName}!\n\nNetwork error: ${error.message}`);
                btn.disabled = false;
                btn.textContent = originalText;
            });
        }
        
        // Update functions - force confirmation dialog to work
        function updateController(deviceId, deviceIp, deviceName) {
            console.log('updateController called with:', deviceId, deviceIp, deviceName);
            
            // Force the browser's native confirm dialog to show
            setTimeout(function() {
                const confirmed = window.confirm(`⚠️ UPDATE CONTROLLER CONFIRMATION\n\nAre you sure you want to update the controller for "${deviceName}"?\n\nDevice IP: ${deviceIp}\n\n⚠️ WARNING: The device may be temporarily unavailable during the update process.\n\nClick OK to proceed or Cancel to abort.`);
                
                if (confirmed) {
                    console.log('User confirmed controller update');
                    const btn = document.querySelector(`[data-device-id="${deviceId}"].update-btn-controller`);
                    if (!btn) {
                        console.error('Could not find controller button for device', deviceId);
                        alert('Error: Could not find update button');
                        return;
                    }
                    
                    const originalText = btn.textContent;
                    btn.disabled = true;
                    btn.textContent = 'Updating...';
                    
                    console.log('Sending controller update request...');
                    
                    fetch('device_update.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `action=update_controller&device_id=${deviceId}&device_ip=${encodeURIComponent(deviceIp)}`
                    })
                    .then(response => {
                        console.log('Controller update response received:', response.status);
                        if (!response.ok) {
                            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                        }
                        return response.json();
                    })
                    .then(data => {
                        console.log('Controller update response data:', data);
                        if (data.success) {
                            alert(`✅ Controller update initiated successfully for ${deviceName}!\n\nResponse: ${data.message || 'Update started'}`);
                        } else {
                            alert(`❌ Controller update failed for ${deviceName}!\n\nError: ${data.error || 'Unknown error'}`);
                        }
                        btn.disabled = false;
                        btn.textContent = originalText;
                    })
                    .catch(error => {
                        console.error('Controller update error:', error);
                        alert(`❌ Controller update failed for ${deviceName}!\n\nNetwork error: ${error.message}`);
                        btn.disabled = false;
                        btn.textContent = originalText;
                    });
                } else {
                    console.log('User cancelled controller update');
                }
            }, 100); // Small delay to bypass extension interference
        }
        
        function updatePod(deviceId, deviceIp, deviceName) {
            console.log('updatePod called with:', deviceId, deviceIp, deviceName);
            
            // Force the browser's native confirm dialog to show
            setTimeout(function() {
                const confirmed = window.confirm(`⚠️ UPDATE POD CONFIRMATION\n\nAre you sure you want to update the pod for "${deviceName}"?\n\nDevice IP: ${deviceIp}\n\n⚠️ WARNING: The device may be temporarily unavailable during the update process.\n\nClick OK to proceed or Cancel to abort.`);
                
                if (confirmed) {
                    console.log('User confirmed pod update');
                    const btn = document.querySelector(`[data-device-id="${deviceId}"].update-btn-pod`);
                    if (!btn) {
                        console.error('Could not find pod button for device', deviceId);
                        alert('Error: Could not find update button');
                        return;
                    }
                    
                    const originalText = btn.textContent;
                    btn.disabled = true;
                    btn.textContent = 'Updating...';
                    
                    console.log('Sending pod update request...');
                    
                    fetch('device_update.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `action=update_pod&device_id=${deviceId}&device_ip=${encodeURIComponent(deviceIp)}`
                    })
                    .then(response => {
                        console.log('Pod update response received:', response.status);
                        if (!response.ok) {
                            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                        }
                        return response.json();
                    })
                    .then(data => {
                        console.log('Pod update response data:', data);
                        if (data.success) {
                            alert(`✅ Pod update initiated successfully for ${deviceName}!\n\nResponse: ${data.message || 'Update started'}`);
                        } else {
                            alert(`❌ Pod update failed for ${deviceName}!\n\nError: ${data.error || 'Unknown error'}`);
                        }
                        btn.disabled = false;
                        btn.textContent = originalText;
                    })
                    .catch(error => {
                        console.error('Pod update error:', error);
                        alert(`❌ Pod update failed for ${deviceName}!\n\nNetwork error: ${error.message}`);
                        btn.disabled = false;
                        btn.textContent = originalText;
                    });
                } else {
                    console.log('User cancelled pod update');
                }
            }, 100); // Small delay to bypass extension interference
        }('Controller update error:', error);
                    alert(`❌ Controller update failed for ${deviceName}!\n\nNetwork error: ${error.message}`);
                    btn.disabled = false;
                    btn.textContent = originalText;
                });
            } else {
                console.log('User cancelled controller update');
            }
        }
        
        function updatePod(deviceId, deviceIp, deviceName) {
            console.log('updatePod called with:', deviceId, deviceIp, deviceName);
            
            if (confirm(`⚠️ UPDATE POD CONFIRMATION\n\nAre you sure you want to update the pod for "${deviceName}"?\n\nDevice IP: ${deviceIp}\n\n⚠️ WARNING: The device may be temporarily unavailable during the update process.\n\nClick OK to proceed or Cancel to abort.`)) {
                console.log('User confirmed pod update');
                const btn = document.querySelector(`[data-device-id="${deviceId}"].update-btn-pod`);
                if (!btn) {
                    console.error('Could not find pod button for device', deviceId);
                    alert('Error: Could not find update button');
                    return;
                }
                
                const originalText = btn.textContent;
                btn.disabled = true;
                btn.textContent = 'Updating...';
                
                console.log('Sending pod update request...');
                
                fetch('device_update.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `action=update_pod&device_id=${deviceId}&device_ip=${encodeURIComponent(deviceIp)}`
                })
                .then(response => {
                    console.log('Pod update response received:', response.status);
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    return response.json();
                })
                .then(data => {
                    console.log('Pod update response data:', data);
                    if (data.success) {
                        alert(`✅ Pod update initiated successfully for ${deviceName}!\n\nResponse: ${data.message || 'Update started'}`);
                    } else {
                        alert(`❌ Pod update failed for ${deviceName}!\n\nError: ${data.error || 'Unknown error'}`);
                    }
                    btn.disabled = false;
                    btn.textContent = originalText;
                })
                .catch(error => {
                    console.error('Pod update error:', error);
                    alert(`❌ Pod update failed for ${deviceName}!\n\nNetwork error: ${error.message}`);
                    btn.disabled = false;
                    btn.textContent = originalText;
                });
            } else {
                console.log('User cancelled pod update');
            }
        }
        
        // Close modals when clicking outside
        window.onclick = function(event) {
            const addModal = document.getElementById('addModal');
            const editModal = document.getElementById('editModal');
            const deleteModal = document.getElementById('deleteModal');
            if (event.target == addModal) {
                closeAddModal();
            }
            if (event.target == editModal) {
                closeEditModal();
            }
            if (event.target == deleteModal) {
                closeDeleteModal();
            }
        }
        
        // Close modals with Escape key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeAddModal();
                closeEditModal();
                closeDeleteModal();
            }
        });
    </script>
</body>
</html>