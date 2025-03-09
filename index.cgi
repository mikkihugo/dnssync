#!/bin/bash
echo "Content-type: text/html"
echo ""

# Load WHM theme and libraries
source /usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud/lib/init.php

# Process actions if any
action=$(echo "$QUERY_STRING" | grep -oP 'action=\K[^&]*')

case "$action" in
    sync_domain)
        domain=$(echo "$QUERY_STRING" | grep -oP 'domain=\K[^&]*')
        if [ ! -z "$domain" ]; then
            /usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud/scripts/run_sync.py --domain "$domain"
            echo "<div class='alert alert-success'>Synchronization for domain $domain initiated.</div>"
        fi
        ;;
    sync_all)
        /usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud/scripts/run_sync.py
        echo "<div class='alert alert-success'>Synchronization for all domains initiated.</div>"
        ;;
    save_config)
        # Process form submission for config.ini
        # Will be handled by a separate PHP script
        ;;
    *)
        # Default: show main status page
        ;;
esac

# Include the header template
include_once("/usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud/templates/header.tmpl");

# Display domains and their sync status
echo "<h2>Domain Synchronization Status</h2>"
echo "<div class='alert alert-info'>Last sync check: $(date)</div>"

# Button to sync all domains
echo "<div class='form-group'>"
echo "<a href='index.cgi?action=sync_all' class='btn btn-primary'>Sync All Domains</a>"
echo "<a href='settings.cgi' class='btn btn-default'>Settings</a>"
echo "</div>"

# Get domain status
domains_output=$(python3 /usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud/scripts/get_domain_status.py)

# Display domain table
echo "<table class='table table-bordered table-striped'>"
echo "<thead><tr><th>Domain</th><th>Status</th><th>Last Sync</th><th>Actions</th></tr></thead>"
echo "<tbody>"
echo "$domains_output"
echo "</tbody></table>"

# Include the footer template
include_once("/usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud/templates/footer.tmpl");