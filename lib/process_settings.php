<?php
// Process settings form submission

// Require admin access
require_once('init.php');

// Configuration file path
$configFile = "/usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud/config/config.ini";

// Check if form was submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['configContent'])) {
    // Create backup of current config
    $backupFile = $configFile . ".backup." . date("YmdHis");
    copy($configFile, $backupFile);
    
    // Update the config file
    file_put_contents($configFile, $_POST['configContent']);
    
    // Redirect back to settings page with success message
    header("Location: ../settings.cgi?updated=1");
    exit;
}

// If we got here without POST data, redirect back to settings page
header("Location: ../settings.cgi");
exit;