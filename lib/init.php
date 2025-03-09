<?php
// This script initializes the WHM environment for the Central Cloud plugin

// Ensure we're in WHM context
if (!isset($_ENV['REMOTE_USER']) || $_ENV['REMOTE_USER'] !== 'root') {
    http_response_code(403);
    echo "<h1>Access Denied</h1>";
    echo "<p>This plugin requires WHM administrator access.</p>";
    exit;
}

// Include WHM header functions
require_once('/usr/local/cpanel/php/WHM.php');

// Set up page header
echo WHM::header('Central Cloud PowerDNS Synchronization', 0, 0);

// Helper function to include templates
function include_once($file) {
    if (file_exists($file)) {
        include($file);
        return true;
    }
    return false;
}