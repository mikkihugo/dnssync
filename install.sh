#!/bin/bash

# Central Cloud - PowerDNS Synchronization Plugin for WHM
# Installation Script

# Exit on any error
set -e

PLUGIN_DIR="/usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud"

# Check if running as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Create plugin directories
echo "Creating plugin directories..."
mkdir -p "$PLUGIN_DIR"
mkdir -p "$PLUGIN_DIR/templates"
mkdir -p "$PLUGIN_DIR/scripts"
mkdir -p "$PLUGIN_DIR/hooks"
mkdir -p "$PLUGIN_DIR/config"
mkdir -p "$PLUGIN_DIR/lib"

# Copy files to their respective locations
echo "Copying plugin files..."
cp -f index.cgi "$PLUGIN_DIR/"
cp -f settings.cgi "$PLUGIN_DIR/"
cp -f templates/* "$PLUGIN_DIR/templates/"
cp -f scripts/* "$PLUGIN_DIR/scripts/"
cp -f hooks/* "$PLUGIN_DIR/hooks/"
cp -f lib/* "$PLUGIN_DIR/lib/"
cp -f dnssync.py "$PLUGIN_DIR/"

# If config.ini doesn't exist, create a default one
if [ ! -f "$PLUGIN_DIR/config/config.ini" ]; then
    echo "Creating default configuration..."
    cp -f config/config.ini.default "$PLUGIN_DIR/config/config.ini"
fi

# Set correct permissions
echo "Setting permissions..."
chmod 700 "$PLUGIN_DIR/index.cgi"
chmod 700 "$PLUGIN_DIR/settings.cgi"
chmod 600 "$PLUGIN_DIR/config/config.ini"
chmod 700 "$PLUGIN_DIR/scripts/"*
chmod 700 "$PLUGIN_DIR/hooks/"*

# Install WHM plugin configuration
echo "Registering WHM plugin..."
cat > /usr/local/cpanel/whostmgr/docroot/cgi/addon_plugins/central_cloud.cpanelplugin <<EOF
name=Central Cloud
url=/cgi/addon_central_cloud/index.cgi
acls=all
group=DNS
icon=centralcloud.png
displayname=Central Cloud
target=_self
EOF

# Copy icon
cp -f centralcloud.png /usr/local/cpanel/whostmgr/docroot/themes/paper_lantern/icons/

# Install cPanel hooks
echo "Setting up event hooks..."
ln -sf "$PLUGIN_DIR/hooks/postwwwacct" /usr/local/cpanel/hooks/postwwwacct
ln -sf "$PLUGIN_DIR/hooks/postupcp" /usr/local/cpanel/hooks/postupcp

# Setup cron job for periodic synchronization
echo "Setting up cron job..."
(crontab -l 2>/dev/null || echo "") | grep -v "$PLUGIN_DIR" > /tmp/crontab.tmp
echo "0 */12 * * * $PLUGIN_DIR/scripts/run_sync.py > /dev/null 2>&1" >> /tmp/crontab.tmp
crontab /tmp/crontab.tmp
rm /tmp/crontab.tmp

# Check for required dependencies
echo "Checking dependencies..."
pip3 install -q requests configparser dnspython

echo "Installation complete!"
echo "Visit WHM > Plugins > Central Cloud to access the plugin"