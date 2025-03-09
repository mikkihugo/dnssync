#!/usr/bin/env python3

import os
import sys
import json
import subprocess
import configparser

# Base path for the plugin
PLUGIN_BASE = "/usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud"
CONFIG_FILE = f"{PLUGIN_BASE}/config/config.ini"

def main():
    # Read configuration
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    active_zones_file = config.get('Settings', 'active_zones_file')
    
    # Get active zones
    active_zones = set()
    if os.path.isfile(active_zones_file):
        with open(active_zones_file) as f:
            active_zones = {line.strip() for line in f}
    
    # Get all cPanel zones
    try:
        cpanel_cmd = subprocess.getoutput('whmapi1 listzones --output=json')
        cpanel_data = json.loads(cpanel_cmd)
        cpanel_zones = {z['domain'].lower().rstrip('.') for z in cpanel_data['data']['zone']}
    except (json.JSONDecodeError, KeyError) as e:
        print(f"<tr><td colspan='4'>Error: Failed to get domain list - {e}</td></tr>")
        return 1
    
    # Generate table rows for each domain
    for domain in sorted(cpanel_zones):
        if domain in active_zones:
            status = "<span style='color:green'>Synchronized</span>"
        else:
            status = "<span style='color:orange'>Not synchronized</span>"
        
        # Get last sync time (would come from a log or metadata in a real implementation)
        last_sync = "N/A"
        
        # Actions button
        actions = f"<a href='index.cgi?action=sync_domain&domain={domain}' class='btn btn-sm btn-primary'>Sync Now</a>"
        
        print(f"<tr><td>{domain}</td><td>{status}</td><td>{last_sync}</td><td>{actions}</td></tr>")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())