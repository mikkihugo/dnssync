# Central Cloud - PowerDNS Synchronization Plugin for WHM/cPanel

This plugin provides integration between cPanel's BIND DNS server and a PowerDNS server, allowing for automatic synchronization of DNS zones.

Not for production use.

## Features

- Automatic detection of new domains in cPanel
- AXFR synchronization between cPanel and PowerDNS
- Domain delegation verification
- Cleanup of inactive domains
- Support for DNS zone management metadata
- SOA drift detection

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/mikkihugo/dnssync.git
   cd dnssync
   ```

2. Run the installation script:
   ```
   chmod +x install.sh
   ./install.sh
   ```

3. Configure the plugin:
   - Go to WHM > Plugins > Central Cloud
   - Update the settings as needed (API key, nameservers, etc.)

## Configuration

Edit the configuration file at `/usr/local/cpanel/whostmgr/docroot/cgi/addon_central_cloud/config/config.ini` or use the settings page in the WHM interface.

Key settings:
- `pdns_api_url`: URL to your PowerDNS API
- `pdns_api_key`: Your PowerDNS API key
- `nameservers`: Comma-separated list of authoritative nameservers
- `excluded_domains`: Domains to exclude from synchronization

## Usage

The plugin will automatically synchronize domains when:
- A new domain is added to cPanel
- A domain is removed from cPanel
- The scheduled cron job runs (every 12 hours)

You can also manually trigger synchronization for all domains or specific domains from the plugin interface.

## Uninstallation

Run the uninstallation script:
```
chmod +x uninstall.sh
./uninstall.sh
```

## License

This project is licensed under the terms of the MIT license.
