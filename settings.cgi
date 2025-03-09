#!/bin/bash
echo "Content-type: text/html"
echo ""

# Load WHM theme and libraries
source /usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud/lib/init.php

# Process form submission if applicable
if [ "$REQUEST_METHOD" = "POST" ]; then
    # Process the form submission and update config.ini
    # Will be implemented as a separate PHP script
    echo "<div class='alert alert-success'>Settings updated successfully.</div>"
fi

# Include the header template
include_once("/usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud/templates/header.tmpl");

# Get current config
CONFIG_FILE="/usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud/config/config.ini"

echo "<h2>Central Cloud Settings</h2>"
echo "<form method='post' action='settings.cgi'>"

# Display config.ini in an editable form
echo "<div class='form-group'>"
echo "<label for='configContent'>Configuration File</label>"
echo "<textarea id='configContent' name='configContent' class='form-control' rows='20'>"
cat "$CONFIG_FILE"
echo "</textarea>"
echo "</div>"

echo "<button type='submit' class='btn btn-primary'>Save Settings</button>"
echo "<a href='index.cgi' class='btn btn-default'>Back to Dashboard</a>"
echo "</form>"

# Include the footer template
include_once("/usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud/templates/footer.tmpl");