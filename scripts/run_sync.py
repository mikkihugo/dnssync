#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse

# Base path for the plugin
PLUGIN_BASE = "/usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud"
DNSSYNC_SCRIPT = f"{PLUGIN_BASE}/dnssync.py"
CONFIG_FILE = f"{PLUGIN_BASE}/config/config.ini"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--domain', help='Process a single domain explicitly')
    args = parser.parse_args()

    # Ensure we're in the right directory for relative paths
    os.chdir(PLUGIN_BASE)

    # Build command
    cmd = [
        DNSSYNC_SCRIPT,
        '--write',  # Always write changes
    ]
    
    if args.domain:
        cmd.extend(['--domain', args.domain])
    
    # Run the dnssync script
    try:
        result = subprocess.run(cmd, check=True)
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"Error running dnssync: {e}", file=sys.stderr)
        return e.returncode

if __name__ == "__main__":
    sys.exit(main())