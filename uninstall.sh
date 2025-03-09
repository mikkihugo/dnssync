#!/bin/bash

# Central Cloud - PowerDNS Synchronization Plugin for WHM
# Uninstallation Script

# Exit on any error
set -e

PLUGIN_DIR="/usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud"

# Check if running as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

echo "Uninstalling Central Cloud WHM Plugin..."

# Remove WHM plugin configuration
echo "Removing WHM plugin registration..."
rm -f /usr/local/cpanel/whostmgr/docroot/cgi/addon_plugins/central_cloud.cpanelplugin

# Remove icon
echo "Removing icon..."
rm -f /usr/local/cpanel/whostmgr/docroot/themes/paper_lantern/icons/centralcloud.png

# Remove hooks
echo "Removing event hooks..."
rm -f /usr/local/cpanel/hooks/postwwwacct/postwwwacct
rm -f /usr/local/cpanel/hooks/postupcp/postupcp

# Remove cron job
echo "Removing cron job..."
(crontab -l 2>/dev/null | grep -v "$PLUGIN_DIR") | crontab -

echo "Do you want to remove configuration files? (This will delete your settings)"
read -p "Remove config files? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Removing plugin files..."
    rm -rf "$PLUGIN_DIR"
    echo "All files removed."
else
    echo "Configuration preserved. Only hooks and plugin registration removed."
fi

echo "Uninstallation complete!"