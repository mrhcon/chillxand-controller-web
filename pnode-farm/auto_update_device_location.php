<?php
/**
 * auto_update_device_location.php
 * Location Update Script
 * Runs every 2 hours to update device locations based on IP addresses
 * Only updates if location is empty or if geolocation lookup succeeds
 */

require_once 'db_connect.php';
require_once 'functions.php';

// Logging function
function logMessage($message) {
    $timestamp = date('Y-m-d H:i:s');
    $logFile = __DIR__ . '/location_update.log';
    file_put_contents($logFile, "[$timestamp] $message" . PHP_EOL, FILE_APPEND | LOCK_EX);
    echo "[$timestamp] $message" . PHP_EOL;
}

// Function to get location from IP address (City, State/Region, Country only)
function getLocationFromIP($ip) {
    // Skip private/local IP addresses
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return null;
    }
    
    // Free geolocation services with fallback - returns only city/state/country
    $geoServices = [
        [
            'url' => "http://ip-api.com/json/{$ip}?fields=status,country,regionName,city",
            'parser' => function($data) {
                if (isset($data['status']) && $data['status'] === 'success') {
                    $parts = array_filter([
                        $data['city'] ?? null,
                        $data['regionName'] ?? null,
                        $data['country'] ?? null
                    ]);
                    return !empty($parts) ? implode(', ', $parts) : null;
                }
                return null;
            }
        ],
        [
            'url' => "https://ipapi.co/{$ip}/json/",
            'parser' => function($data) {
                if (!isset($data['error'])) {
                    $parts = array_filter([
                        $data['city'] ?? null,
                        $data['region'] ?? null,
                        $data['country_name'] ?? null
                    ]);
                    return !empty($parts) ? implode(', ', $parts) : null;
                }
                return null;
            }
        ],
        [
            'url' => "http://www.geoplugin.net/json.gp?ip={$ip}",
            'parser' => function($data) {
                if (isset($data['geoplugin_status']) && $data['geoplugin_status'] == 200) {
                    $parts = array_filter([
                        $data['geoplugin_city'] ?? null,
                        $data['geoplugin_regionName'] ?? null,
                        $data['geoplugin_countryName'] ?? null
                    ]);
                    return !empty($parts) ? implode(', ', $parts) : null;
                }
                return null;
            }
        ]
    ];
    
    foreach ($geoServices as $index => $service) {
        try {
            $context = stream_context_create([
                'http' => [
                    'timeout' => 10,
                    'user_agent' => 'Mozilla/5.0 (compatible; LocationUpdater/1.0)'
                ]
            ]);
            
            $response = @file_get_contents($service['url'], false, $context);
            if ($response === false) {
                continue;
            }
            
            $data = json_decode($response, true);
            if (!$data) {
                continue;
            }
            
            $location = $service['parser']($data);
            if ($location) {
                return $location;
            }
            
        } catch (Exception $e) {
            logMessage("Error with geolocation service $index: " . $e->getMessage());
            continue;
        }
        
        // Rate limiting - wait 1 second between service calls
        sleep(1);
    }
    
    return null;
}

// Main execution
try {
    logMessage("Starting location update process...");
    
    // Use existing database connection from db_connect.php
    if (!isset($pdo)) {
        throw new Exception("Database connection not available");
    }
    
    // Get devices with empty locations or that need updates
    $stmt = $pdo->prepare("
        SELECT id, username, pnode_name, pnode_ip, location 
        FROM devices 
        WHERE pnode_ip IS NOT NULL 
        AND pnode_ip != '' 
        AND pnode_ip != '0.0.0.0'
        AND pnode_ip != '127.0.0.1'
        AND (location IS NULL OR location = '' OR location = 'Unknown')
        ORDER BY registration_date DESC
    ");
    
    $stmt->execute();
    $devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $totalDevices = count($devices);
    $updatedCount = 0;
    $errorCount = 0;
    $skippedCount = 0;
    
    logMessage("Found $totalDevices devices to process");
    
    foreach ($devices as $device) {
        $deviceId = $device['id'];
        $deviceName = $device['pnode_name'];
        $deviceIP = $device['pnode_ip'];
        $username = $device['username'];
        
        logMessage("Processing device: $deviceName (ID: $deviceId, IP: $deviceIP, User: $username)");
        
        // Skip obvious local/private IPs that might have slipped through
        if (preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.)/', $deviceIP)) {
            logMessage("- Skipping private IP: $deviceIP for device $deviceName");
            $skippedCount++;
            continue;
        }
        
        $location = getLocationFromIP($deviceIP);
        
        if ($location) {
            try {
                // Update the device with the new location
                $updateStmt = $pdo->prepare("UPDATE devices SET location = ? WHERE id = ?");
                
                if ($updateStmt->execute([$location, $deviceId])) {
                    $updatedCount++;
                    logMessage("✓ Updated device $deviceName: $location");
                    
                    // Log this interaction using the existing function if available
                    if (function_exists('logInteraction')) {
                        // Try to get user_id for logging (optional)
                        $userStmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
                        $userStmt->execute([$username]);
                        $user = $userStmt->fetch(PDO::FETCH_ASSOC);
                        $userId = $user ? $user['id'] : null;
                        
                        if ($userId) {
                            logInteraction($pdo, $userId, $username, 'location_updated', 
                                "Device: $deviceName, IP: $deviceIP, Location: $location");
                        }
                    }
                } else {
                    $errorCount++;
                    logMessage("✗ Failed to update device $deviceName in database");
                }
            } catch (PDOException $e) {
                $errorCount++;
                logMessage("✗ Database error updating device $deviceName: " . $e->getMessage());
            }
        } else {
            logMessage("- No location found for device $deviceName (IP: $deviceIP)");
        }
        
        // Rate limiting - wait 2 seconds between requests to be respectful
        sleep(2);
    }
    
    logMessage("Location update completed. Updated: $updatedCount, Errors: $errorCount, Skipped: $skippedCount, Total processed: $totalDevices");
    
    // Log summary to interaction log if function exists
    if (function_exists('logInteraction')) {
        // Use a system user ID if available, or just log without user context
        $summaryMsg = "Location update batch: Updated $updatedCount devices, $errorCount errors, $skippedCount skipped";
        // You could create a system user for these automated tasks, or just use user ID 1 (admin)
    }
    
} catch (PDOException $e) {
    logMessage("Database error: " . $e->getMessage());
    exit(1);
} catch (Exception $e) {
    logMessage("General error: " . $e->getMessage());
    exit(1);
}

logMessage("Script finished successfully");
?>