#!/usr/bin/env python3

"""
cPanel DNS Synchronization Script for PowerDNS

This script synchronizes DNS zones between cPanel's BIND DNS and a PowerDNS server.
It detects new domains in cPanel and creates/updates them in PowerDNS with proper
configuration for bidirectional synchronization via AXFR.

Features:
- Automatic detection of new domains in cPanel
- AXFR synchronization between cPanel and PowerDNS
- Domain delegation verification
- Cleanup of inactive domains
- Support for DNS zone management metadata
- SOA drift detection between cPanel and PowerDNS

Usage:
  ./dnssync.py [options] [domain]

Configuration:
  The script reads settings from config.ini in the same directory
"""

# Standard library imports
import sys
import os
import subprocess
import json
import logging
import argparse
import fcntl
import re
import time
from datetime import datetime, timedelta

# Third-party imports
import requests
import configparser
import dns.resolver
import dns.query
import dns.message

# Global configuration
config = configparser.ConfigParser()
config.read('config.ini')

ACTIVE_ZONES_FILE = config.get('Settings', 'active_zones_file')
REMOVE_ZONES_FILE = config.get('Settings', 'remove_zones_file')
LOG_FILE = config.get('Settings', 'log_file')
PDNS_API_URL = config.get('Settings', 'pdns_api_url').rstrip('/')
PDNS_API_KEY = config.get('Settings', 'pdns_api_key')
EXPECTED_NS = sorted(ns.strip().lower().rstrip('.') for ns in config.get('Settings', 'nameservers').split(','))
MASTERNS = config.get('Settings', 'masterns')
EXCLUDED_DOMAINS = {d.strip().lower() for d in config.get('Settings', 'excluded_domains', fallback='').split(',') if d.strip()}
CPANEL_SERVER_IP = subprocess.getoutput('hostname -I').strip().split()[0]
ENABLE_BIDIRECTIONAL = config.getboolean('Settings', 'enable_bidirectional', fallback=True)
DNSSEC_ENABLED = config.getboolean('Settings', 'dnssec_enabled', fallback=False)


def setup_logging(silent):
    """
    Configure logging to both file and stdout (unless silent)
    
    Args:
        silent: Boolean indicating whether to suppress console output
    """
    handlers = []
    if not silent:
        handlers.append(logging.StreamHandler(sys.stdout))
    handlers.append(logging.FileHandler(LOG_FILE))
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s',
        handlers=handlers
    )


def single_instance():
    """
    Ensure only one instance of the script is running using file locking
    
    Raises:
        SystemExit: If another instance is already running
    """
    lockfile = '/tmp/dnssync.lock'
    fp = open(lockfile, 'w')
    try:
        fcntl.flock(fp, fcntl.LOCK_EX|fcntl.LOCK_NB)
    except IOError:
        logging.error("Script already running.")
        sys.exit(1)


def pdns_req(method, domain, data=None, retry_count=3):
    """
    Make an API request to PowerDNS with automatic retries
    
    Args:
        method: HTTP method (GET, PUT, POST, etc)
        domain: Domain name for the API endpoint
        data: JSON data payload for PUT/POST requests
        retry_count: Number of retries on failure
        
    Returns:
        Response object from requests
    """
    headers = {'X-API-Key': PDNS_API_KEY, 'Content-Type': 'application/json'}
    url = f"{PDNS_API_URL}/api/v1/servers/localhost/zones/{domain}."
    
    for attempt in range(retry_count):
        try:
            response = requests.request(method, url, headers=headers, json=data, timeout=10)
            if response.ok or response.status_code == 404:
                return response
                
            # Only retry on server errors
            if response.status_code < 500:
                return response
                
            logging.warning(f"Attempt {attempt+1}/{retry_count} failed for {domain}: {response.status_code}")
            time.sleep(1)  # Wait before retrying
            
        except (requests.ConnectionError, requests.Timeout) as e:
            logging.warning(f"Connection error on attempt {attempt+1}/{retry_count} for {domain}: {e}")
            time.sleep(1)  # Wait before retrying
    
    # If we get here, all retries failed
    return response


def update_pdns(domain, zone_data, dryrun, verbose):
    """
    Update a zone in PowerDNS
    
    Args:
        domain: Domain name to update
        zone_data: Dictionary containing zone configuration
        dryrun: Boolean indicating whether to perform the update or just simulate
        verbose: Boolean indicating whether to log detailed information
    """
    if dryrun:
        if verbose:
            logging.info(f"[Dry-run] Would update PDNS {domain}: {json.dumps(zone_data)}")
        else:
            logging.info(f"[Dry-run] Would update PDNS zone: {domain}")
        return
    
    response = pdns_req('PUT', domain, zone_data)
    if response.ok:
        logging.info(f"Updated {domain} in PDNS.")
    else:
        logging.error(f"Failed updating {domain}: {response.status_code}, {response.text}")


def create_pdns_zone(domain, dryrun, verbose):
    """
    Create a new zone in PowerDNS
    
    Args:
        domain: Domain name to create
        dryrun: Boolean indicating whether to perform the creation or just simulate
        verbose: Boolean indicating whether to log detailed information
    """
    masters = [CPANEL_SERVER_IP]  # Only cPanel as master

    # Define zone metadata
    metadata = [
        {"kind": "ALLOW-AXFR-FROM", "content": CPANEL_SERVER_IP},
        {"kind": "AXFR-SOURCE", "content": CPANEL_SERVER_IP},
        {"kind": "ALSO-NOTIFY", "content": CPANEL_SERVER_IP},
        {"kind": "MANAGED-BY", "content": "cpanel-dnssync-script"},
        {"kind": "SYNC-DATE", "content": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"kind": "API-RECTIFY", "content": "1"},
        {"kind": "RECTIFY-ZONE", "content": "1"},
        {"kind": "SOA-EDIT-API", "content": "INCEPTION-INCREMENT"}
    ]
    
    # Add DNSSEC settings if enabled
    if DNSSEC_ENABLED:
        metadata.append({"kind": "DNSSEC-PREVENT-SYNC", "content": "1"})
    
    zone_data = {
        "name": f"{domain}.",
        "kind": "Native",  # Native for MySQL backend
        "masters": masters,
        "nameservers": EXPECTED_NS,
        "metadata": metadata
    }

    if dryrun:
        if verbose:
            logging.info(f"[Dry-run] Would create PDNS zone {domain} in bi-directional mode: {json.dumps(zone_data)}")
        else:
            logging.info(f"[Dry-run] Would create PDNS zone in bi-directional mode: {domain}")
        return

    response = requests.post(
        f"{PDNS_API_URL}/api/v1/servers/localhost/zones",
        headers={'X-API-Key': PDNS_API_KEY, 'Content-Type':'application/json'},
        json=zone_data
    )
    
    if response.ok:
        logging.info(f"Created Native zone {domain} with bi-directional sync configuration")
        
        # Setup DNSSEC if enabled
        if DNSSEC_ENABLED and not dryrun:
            setup_dnssec(domain)
    else:
        logging.error(f"Failed creating zone {domain}: {response.status_code}, {response.text}")


def setup_dnssec(domain):
    """
    Setup DNSSEC for a domain by enabling it via the PowerDNS API
    
    Args:
        domain: Domain name to enable DNSSEC for
    """
    try:
        # Enable DNSSEC on the zone
        enable_url = f"{PDNS_API_URL}/api/v1/servers/localhost/zones/{domain}./dnssec"
        response = requests.post(
            enable_url,
            headers={'X-API-Key': PDNS_API_KEY, 'Content-Type': 'application/json'},
            json={}
        )
        
        if response.ok:
            logging.info(f"DNSSEC enabled for {domain}")
            
            # Rectify the zone to ensure all DNSSEC records are properly created
            rectify_url = f"{PDNS_API_URL}/api/v1/servers/localhost/zones/{domain}./rectify"
            rectify_response = requests.put(
                rectify_url,
                headers={'X-API-Key': PDNS_API_KEY}
            )
            
            if rectify_response.ok:
                logging.info(f"Zone {domain} rectified for DNSSEC")
            else:
                logging.error(f"Failed to rectify zone {domain}: {rectify_response.status_code}, {rectify_response.text}")
        else:
            logging.error(f"Failed to enable DNSSEC for {domain}: {response.status_code}, {response.text}")
    except Exception as e:
        logging.error(f"Error setting up DNSSEC for {domain}: {e}")


def load_removal_candidates():
    """
    Load the list of domains marked for potential removal
    
    Returns:
        dict: Dictionary of domain names and when they were marked for removal
    """
    if not os.path.isfile(REMOVE_ZONES_FILE):
        return {}
        
    with open(REMOVE_ZONES_FILE) as f:
        candidates = dict(line.strip().split(',',1) for line in f if ',' in line)
    return candidates


def save_removal_candidates(candidates):
    """
    Save the list of domains marked for potential removal
    
    Args:
        candidates: Dictionary of domain names and when they were marked for removal
    """
    with open(REMOVE_ZONES_FILE, 'w') as f:
        for d, t in candidates.items():
            f.write(f"{d},{t}\n")


def cleanup_inactive_domains(inactive_domains, dryrun, verbose):
    """
    Clear metadata and master settings from inactive domains without deleting them.
    Keeps the domains in PowerDNS but removes our management indicators.
    
    Args:
        inactive_domains: List of domain names to clean up
        dryrun: Boolean indicating whether to perform the cleanup or just simulate
        verbose: Boolean indicating whether to log detailed information
    """
    if not inactive_domains:
        return

    cpanel_hostname = subprocess.getoutput('hostname').strip()
    domains_cleaned = 0

    for domain in inactive_domains:
        r = pdns_req('GET', domain)
        if not r.ok:
            logging.warning(f"Failed to retrieve inactive domain {domain} for cleanup: {r.status_code}")
            continue

        zone = r.json()

        # Check if this is one of our managed domains
        is_managed_by_us = False
        for meta in zone.get('metadata', []):
            if meta['kind'] == 'MANAGED-BY' and 'cpanel-dnssync-script' in meta['content']:
                is_managed_by_us = True
                break

        if not is_managed_by_us:
            logging.info(f"Skipping cleanup of {domain} - not managed by this script")
            continue

        # Keep only metadata we don't manage
        preserved_metadata = [m for m in zone.get('metadata', []) if m['kind'] not in
                            ['ALLOW-AXFR-FROM', 'AXFR-SOURCE', 'ALSO-NOTIFY', 'MANAGED-BY',
                             'SYNC-DATE', 'DNSSEC-PREVENT-SYNC', 'API-RECTIFY', 'RECTIFY-ZONE',
                             'SOA-EDIT-API', 'SOA-EDIT-DNSUPDATE']]

        # Add a single metadata entry to indicate it was previously managed by us
        preserved_metadata.append({
            'kind': 'FORMERLY-MANAGED-BY',
            'content': f'cpanel-dnssync-script on {cpanel_hostname} (inactive since {datetime.now().strftime("%Y-%m-%d")})'
        })

        # Update the zone - clear our masters and metadata but keep the domain
        zone['metadata'] = preserved_metadata
        zone['masters'] = []  # Clear masters list

        if dryrun:
            if verbose:
                logging.info(f"[Dry-run] Would clean metadata from inactive domain {domain}")
            else:
                logging.info(f"[Dry-run] Would clean metadata from inactive domain")
        else:
            response = pdns_req('PUT', domain, zone)
            if response.ok:
                logging.info(f"Cleaned metadata from inactive domain {domain}")
                domains_cleaned += 1
            else:
                logging.error(f"Failed cleaning metadata from {domain}: {response.status_code}, {response.text}")

    if not dryrun:
        logging.info(f"Cleaned metadata from {domains_cleaned} inactive domains")


def check_authoritative_ns(domain, expected_ns):
    """
    Performs a comprehensive check of domain nameserver delegation:
    1. Checks local zone file for correct NS records
    2. Traces the delegation path from root servers to verify authoritative nameservers

    Args:
        domain: The domain to check
        expected_ns: List of expected nameserver hostnames

    Returns:
        bool: True if delegation is correct, False otherwise
    """
    delegation_result = {
        'local_check': False,
        'auth_check': False,
        'errors': []
    }

    # Normalize expected nameservers (ensure they're sorted, lowercase, without trailing dots)
    expected = sorted(ns.lower().rstrip('.') for ns in expected_ns)

    # STEP 1: Check local zone file
    try:
        # Check if the domain exists in the zone file
        zone_file = f"/var/named/{domain}.db"
        if not os.path.exists(zone_file):
            # Try alternative location
            zone_file = f"/var/named/data/{domain}.db"
            if not os.path.exists(zone_file):
                delegation_result['errors'].append(f"Zone file for {domain} not found")
            else:
                # Found the zone file, now check the NS records
                with open(zone_file, 'r') as f:
                    zone_content = f.read()

                # Look for NS records in the zone file
                ns_pattern = re.compile(r'^(?:\S+\s+)?IN\s+NS\s+(\S+)', re.MULTILINE | re.IGNORECASE)
                ns_matches = ns_pattern.findall(zone_content)

                if not ns_matches:
                    delegation_result['errors'].append(f"No NS records found in zone file for {domain}")
                else:
                    # Normalize found NS records
                    local_ns = sorted(ns.lower().rstrip('.') for ns in ns_matches)

                    # Compare with expected NS
                    if set(local_ns) == set(expected):
                        delegation_result['local_check'] = True
                        logging.info(f"[Local NS check passed] {domain}: {local_ns}")
                    else:
                        delegation_result['errors'].append(
                            f"NS mismatch in zone file: expected {expected}, found {local_ns}")

    except Exception as e:
        delegation_result['errors'].append(f"Error checking local zone file: {e}")

    # STEP 2: Check actual DNS delegation through the authoritative chain
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5

        # Get TLD by splitting domain
        tld = '.'.join(domain.split('.')[-1:])

        # Query root servers for TLD nameservers
        try:
            # First try to get the TLD nameservers
            ans_tld = resolver.resolve(tld, 'NS')
            tld_nameservers = sorted(str(rr.target).rstrip('.').lower() for rr in ans_tld)
            logging.debug(f"TLD nameservers for {tld}: {tld_nameservers}")

            # Get IP addresses for the TLD nameservers
            tld_ns_ips = []
            for ns in tld_nameservers[:2]:  # Only try first two for efficiency
                try:
                    ip_answers = resolver.resolve(ns, 'A')
                    tld_ns_ips.extend(ip.address for ip in ip_answers)
                except Exception:
                    continue

            if not tld_ns_ips:
                delegation_result['errors'].append(f"Could not resolve any TLD nameserver IPs for {tld}")
                return False

            # Query TLD nameservers for the domain's authoritative nameservers
            auth_ns_records = set()
            query = dns.message.make_query(domain, dns.rdatatype.NS)

            for ip in tld_ns_ips[:2]:  # Try up to 2 TLD nameservers
                try:
                    resp = dns.query.udp(query, ip, timeout=3)
                    ns_rrsets = []

                    # Check answer and authority sections
                    for section in [resp.answer, resp.authority]:
                        for rrset in section:
                            if rrset.rdtype == dns.rdatatype.NS:
                                ns_rrsets.append(rrset)

                    # Extract nameservers from RRsets
                    for rrset in ns_rrsets:
                        for rr in rrset:
                            auth_ns_records.add(str(rr).lower().rstrip('.'))
                except Exception as e:
                    logging.debug(f"Error querying TLD NS {ip} for {domain}: {e}")
                    continue

            if auth_ns_records:
                auth_ns = sorted(auth_ns_records)

                # Compare with expected NS
                if set(auth_ns) == set(expected):
                    delegation_result['auth_check'] = True
                    logging.info(f"[Delegation check passed] {domain}: {auth_ns}")
                else:
                    delegation_result['errors'].append(
                        f"Delegation mismatch: expected {expected}, actual {auth_ns}")
            else:
                delegation_result['errors'].append(f"No authoritative NS records found for {domain}")

        except dns.resolver.NXDOMAIN:
            delegation_result['errors'].append(f"TLD {tld} does not exist")
        except dns.resolver.NoAnswer:
            delegation_result['errors'].append(f"No NS records found for TLD {tld}")
        except Exception as e:
            delegation_result['errors'].append(f"Error resolving TLD nameservers: {e}")

    except Exception as e:
        delegation_result['errors'].append(f"General error in delegation check: {e}")

    # Determine final result
    if delegation_result['local_check'] and delegation_result['auth_check']:
        return True

    # Log errors if checks failed
    for error in delegation_result['errors']:
        logging.warning(error)

    return False


def get_affiliated_domains():
    """
    Get all domains affiliated with active user accounts in cPanel by
    combining main domains, addon domains, parked domains, and subdomains.
    
    Returns:
        set: Set of domain names affiliated with active accounts
    """
    affiliated_domains = set()

    # Get all user accounts
    account_cmd = subprocess.getoutput('whmapi1 listaccts --output=json')
    try:
        account_data = json.loads(account_cmd)
        accounts = [acc['user'] for acc in account_data['data']['acct'] if acc['suspended'] == 0]
    except (json.JSONDecodeError, KeyError) as e:
        logging.error(f"Error parsing account data: {e}")
        return affiliated_domains

    logging.info(f"Found {len(accounts)} active user accounts")

    # Get main domains from listzones
    zones_cmd = subprocess.getoutput('whmapi1 listzones --output=json')
    try:
        zones_data = json.loads(zones_cmd)
        main_domains = {z['domain'].lower().rstrip('.') for z in zones_data['data']['zone']}
        affiliated_domains.update(main_domains)
        logging.info(f"Found {len(main_domains)} main domains from listzones")
    except (json.JSONDecodeError, KeyError) as e:
        logging.error(f"Error parsing zone data: {e}")

    # Get addon domains for each account
    total_addons = 0
    for user in accounts:
        addon_cmd = subprocess.getoutput(f'uapi --user={user} DomainInfo list_domains --output=json')
        try:
            addon_data = json.loads(addon_cmd)
            if addon_data['result']['status'] == 1:
                # Add addon domains
                addon_domains = {d.lower().rstrip('.') for d in addon_data['result']['data']['addon_domains']}
                affiliated_domains.update(addon_domains)
                total_addons += len(addon_domains)

                # Add parked/aliased domains
                parked_domains = {d.lower().rstrip('.') for d in addon_data['result']['data']['parked_domains']}
                affiliated_domains.update(parked_domains)

                # We don't add subdomains as they typically don't have their own DNS zone
        except (json.JSONDecodeError, KeyError) as e:
            logging.error(f"Error parsing addon domain data for user {user}: {e}")

    logging.info(f"Found {total_addons} addon domains across all accounts")

    # Get domains from DNS zone files directly as a fallback
    try:
        zone_files = set(f.replace('.db', '') for f in os.listdir('/var/named')
                      if f.endswith('.db') and not f.startswith('named'))
        logging.info(f"Found {len(zone_files)} zone files in /var/named")

        # Filter only zones that have corresponding zone file
        zone_file_domains = {d for d in affiliated_domains if d in zone_files}
        logging.info(f"{len(zone_file_domains)} of {len(affiliated_domains)} domains have zone files")
    except Exception as e:
        logging.error(f"Error reading zone files: {e}")

    return affiliated_domains


def load_active_zones():
    """
    Load previously processed active zones from file
    
    Returns:
        set: Set of domain names that were previously processed
    """
    if not os.path.isfile(ACTIVE_ZONES_FILE):
        return set()
    with open(ACTIVE_ZONES_FILE) as f:
        return {line.strip() for line in f}


def check_zone_drift(domain):
    """
    Check if zone data has drifted between cPanel and PowerDNS.
    For AXFR-synced zones, we mainly care about SOA serial numbers.
    
    Uses the PowerDNS API to get the SOA from PowerDNS, and local DNS for cPanel.
    
    Args:
        domain: Domain name to check for drift
    
    Returns:
        tuple: (has_drift, details) where details explains any drift found
    """
    # Get SOA from cPanel local DNS
    try:
        # Check if dig command is available
        dig_check = subprocess.run(['which', 'dig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if dig_check.returncode != 0:
            logging.warning("dig command not found, skipping SOA drift check")
            return False, "dig command not available"
            
        # Query local BIND for SOA
        cmd = f"dig @127.0.0.1 {domain} SOA +short"
        cpanel_soa = subprocess.getoutput(cmd)
        
        if not cpanel_soa:
            return False, f"No SOA record found in cPanel for {domain}"
            
        # Extract serial from SOA
        cpanel_serial = cpanel_soa.split()[2] if len(cpanel_soa.split()) > 2 else None
        
        if not cpanel_serial:
            return False, f"Could not extract SOA serial from cPanel for {domain}"
            
        # Get SOA from PowerDNS via API
        pdns_resp = pdns_req('GET', domain)
        if not pdns_resp.ok:
            return True, f"Could not get zone {domain} from PowerDNS API: {pdns_resp.status_code}"
            
        zone_data = pdns_resp.json()
        
        # Find SOA record
        pdns_serial = None
        for record in zone_data.get('records', []):
            if record.get('type') == 'SOA':
                # SOA format: primary_ns email serial refresh retry expire minimum
                soa_parts = record.get('content', '').split()
                if len(soa_parts) > 2:
                    pdns_serial = soa_parts[2]
                    break
                
        if not pdns_serial:
            return True, f"No SOA record found in PowerDNS for {domain}"
            
        # Compare serials
        if cpanel_serial != pdns_serial:
            return True, f"SOA serial mismatch: cPanel={cpanel_serial}, PowerDNS={pdns_serial}"
            
        return False, "SOA serials match"
        
    except Exception as e:
        logging.error(f"Error checking zone drift for {domain}: {e}")
        return False, f"Error checking drift: {str(e)}"


def refresh_domains_metadata(domains, dryrun, verbose=False):
    """
    Update metadata for a list of domains to ensure they have the latest settings
    
    Args:
        domains: List of domain names to refresh metadata for
        dryrun: Boolean indicating whether to perform updates or just simulate
        verbose: Boolean indicating whether to log detailed information
    """
    updated = 0
    for domain in domains:
        try:
            r = pdns_req('GET', domain)
            if not r.ok:
                logging.warning(f"Failed to get zone {domain} for metadata refresh: {r.status_code}")
                continue

            zone = r.json()
            
            # Keep existing metadata that we don't manage
            preserved_metadata = [m for m in zone.get('metadata', []) if m['kind'] not in
                                ['ALLOW-AXFR-FROM', 'AXFR-SOURCE', 'ALSO-NOTIFY', 'MANAGED-BY',
                                 'SYNC-DATE', 'DNSSEC-PREVENT-SYNC', 'API-RECTIFY', 'RECTIFY-ZONE',
                                 'SOA-EDIT-API', 'SOA-EDIT-DNSUPDATE']]

            # Define updated metadata
            new_metadata = [
                {'kind': 'ALLOW-AXFR-FROM', 'content': CPANEL_SERVER_IP},
                {'kind': 'AXFR-SOURCE', 'content': CPANEL_SERVER_IP},
                {'kind': 'ALSO-NOTIFY', 'content': CPANEL_SERVER_IP},
                {'kind': 'MANAGED-BY', 'content': 'cpanel-dnssync-script'},
                {'kind': 'SYNC-DATE', 'content': datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
                {'kind': 'API-RECTIFY', 'content': '1'},
                {'kind': 'RECTIFY-ZONE', 'content': '1'},
                {'kind': 'SOA-EDIT-API', 'content': 'INCEPTION-INCREMENT'}
            ]
            
            # Add DNSSEC settings if enabled
            if DNSSEC_ENABLED:
                new_metadata.append({"kind": "DNSSEC-PREVENT-SYNC", "content": "1"})

            # Combine preserved and new metadata
            zone['metadata'] = preserved_metadata + new_metadata
            
            # Ensure zone kind is Native
            zone['kind'] = 'Native'
            
            # Update masters to only include cPanel
            zone['masters'] = [CPANEL_SERVER_IP]

            if dryrun:
                if verbose:
                    logging.info(f"[Dry-run] Would refresh metadata for {domain}")
                else:
                    logging.info(f"[Dry-run] Would refresh metadata for domain")
            else:
                response = pdns_req('PUT', domain, zone)
                if response.ok:
                    logging.info(f"Refreshed metadata for {domain}")
                    updated += 1
                else:
                    logging.error(f"Failed refreshing metadata for {domain}: {response.status_code}, {response.text}")
        except Exception as e:
            logging.error(f"Error refreshing metadata for {domain}: {e}")
            
    if not dryrun:
        logging.info(f"Refreshed metadata for {updated} domains")


# New function to determine drift direction
def check_drift_direction(domain):
    """
    Check the direction of zone drift between cPanel and PowerDNS.
    
    Args:
        domain: Domain name to check for drift
        
    Returns:
        tuple: (drift_direction, serial_diff) where:
               drift_direction: 0=no drift, 1=cPanel newer, -1=PowerDNS newer
               serial_diff: Numerical difference between serials
    """
    try:
        # Query local BIND for SOA
        cmd = f"dig @127.0.0.1 {domain} SOA +short"
        cpanel_soa = subprocess.getoutput(cmd)
        
        if not cpanel_soa:
            return 0, 0
            
        # Extract serial from SOA
        cpanel_serial = int(cpanel_soa.split()[2]) if len(cpanel_soa.split()) > 2 else None
        
        if not cpanel_serial:
            return 0, 0
            
        # Get SOA from PowerDNS via API
        pdns_resp = pdns_req('GET', domain)
        if not pdns_resp.ok:
            return 1, 0  # Assume cPanel is right if PowerDNS request fails
            
        zone_data = pdns_resp.json()
        
        # Find SOA record
        pdns_serial = None
        for record in zone_data.get('records', []):
            if record.get('type') == 'SOA':
                soa_parts = record.get('content', '').split()
                if len(soa_