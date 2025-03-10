#!/usr/bin/env python3

import sys, os, subprocess, json, requests, configparser, logging, argparse, fcntl, dns.resolver, dns.query, dns.message, re
from datetime import datetime, timedelta

config = configparser.ConfigParser()
config.read('/opt/scripts/dnssync/config.ini')

ACTIVE_ZONES_FILE = config.get('Settings', 'active_zones_file')
REMOVE_ZONES_FILE = config.get('Settings', 'remove_zones_file')
LOG_FILE = config.get('Settings', 'log_file')
PDNS_API_URL = config.get('Settings', 'pdns_api_url').rstrip('/')
PDNS_API_KEY = config.get('Settings', 'pdns_api_key')
EXPECTED_NS = sorted(ns.strip().lower().rstrip('.') for ns in config.get('Settings', 'nameservers').split(','))
MASTERNS = config.get('Settings', 'masterns')
EXCLUDED_DOMAINS = {d.strip().lower() for d in config.get('Settings', 'excluded_domains', fallback='').split(',') if d.strip()}
CPANEL_SERVER_IP = subprocess.getoutput('hostname -I').strip().split()[0]
# Define the secondary acceptable nameserver set
# Define the secondary acceptable nameserver set
SECONDARY_NS = sorted(['ns1.servercentralen.net', 'ns2.servercentralen.net', 'ns3.servercentralen.net', 'ns4.servercentralen.net'])# Get bidirectional sync setting from config or default to True
ENABLE_BIDIRECTIONAL = config.getboolean('Settings', 'enable_bidirectional', fallback=True)

def setup_logging(silent):
    handlers = [logging.StreamHandler(sys.stdout), logging.FileHandler(LOG_FILE)]
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s', handlers=handlers)

def single_instance():
    lockfile = '/tmp/dnssync.lock'
    fp = open(lockfile, 'w')
    try:
        fcntl.flock(fp, fcntl.LOCK_EX|fcntl.LOCK_NB)
    except:
        logging.error("Script already running.")
        sys.exit(1)

def pdns_req(method, domain, data=None):
    headers = {'X-API-Key': PDNS_API_KEY, 'Content-Type':'application/json'}
    url = f"{PDNS_API_URL}/api/v1/servers/localhost/zones/{domain}."
    return requests.request(method, url, headers=headers, json=data)

def update_pdns(domain, zone_data, dryrun, verbose):
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
    masters = [CPANEL_SERVER_IP]  # Only cPanel as master

    # Use a Native configuration for MySQL backend
    # Define zone metadata
    metadata = [
        {"kind": "ALLOW-AXFR-FROM", "content": CPANEL_SERVER_IP},  # Only allow cPanel to transfer
        {"kind": "AXFR-SOURCE", "content": CPANEL_SERVER_IP},
        {"kind": "ALSO-NOTIFY", "content": CPANEL_SERVER_IP},  # Notify cPanel, not itself
        {"kind": "MANAGED-BY", "content": "cpanel-dnssync-script"},
        {"kind": "SYNC-DATE", "content": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
        {"kind": "DNSSEC-PREVENT-SYNC", "content": "1"},  # Prevent DNSSEC from syncing back to cPanel
        {"kind": "API-RECTIFY", "content": "1"},  # Enable API rectify to increment SOA on API changes
        {"kind": "RECTIFY-ZONE", "content": "1"},  # Auto-rectify zone when DNSSEC records need updating
        {"kind": "SOA-EDIT-API", "content": "INCEPTION-INCREMENT"}  # Increment SOA on API changes
        # Removed SOA-EDIT-DNSUPDATE to prevent AXFR loop
    ]

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

    response = requests.post(f"{PDNS_API_URL}/api/v1/servers/localhost/zones",
                             headers={'X-API-Key': PDNS_API_KEY, 'Content-Type':'application/json'},
                             json=zone_data)
    if response.ok:
        logging.info(f"Created Native zone {domain} with bi-directional sync configuration")
    else:
        logging.error(f"Failed creating zone {domain}: {response.status_code}, {response.text}")

def load_removal_candidates():
    if not os.path.isfile(REMOVE_ZONES_FILE): return {}
    with open(REMOVE_ZONES_FILE) as f:
        candidates = dict(line.strip().split(',',1) for line in f if ',' in line)
    return candidates

def cleanup_inactive_domains(inactive_domains, dryrun, verbose):
    """
    Clear metadata and master settings from inactive domains without deleting them.
    Keeps the domains in PowerDNS but removes our management indicators.
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

    return

def save_removal_candidates(candidates):
    with open(REMOVE_ZONES_FILE,'w') as f:
        for d,t in candidates.items(): f.write(f"{d},{t}\n")

def check_authoritative_ns(domain, expected_ns):
    """
    Performs a comprehensive check of domain nameserver delegation:
    1. Checks local zone file for correct NS records
    2. Traces the delegation path from root servers to verify authoritative nameservers

    Modified to allow a second set of acceptable nameservers

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
    primary_ns = sorted(ns.lower().rstrip('.') for ns in expected_ns)
    secondary_ns = sorted(ns.lower().rstrip('.') for ns in SECONDARY_NS)

    # Create a combined set of all acceptable nameservers
    all_acceptable_ns = set(primary_ns).union(set(secondary_ns))

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

                    # Compare with expected NS - consider it valid if:
                    # 1. It contains the full primary set OR
                    # 2. It contains the full secondary set OR
                    # 3. It contains a valid combination from both sets

                    local_ns_set = set(local_ns)

                    # Check if all local nameservers are in our acceptable set
                    if local_ns_set.issubset(all_acceptable_ns):
                        delegation_result['local_check'] = True
                        logging.info(f"[Local NS check passed] {domain}: {local_ns}")
                    else:
                        delegation_result['errors'].append(
                            f"NS mismatch in zone file: expected subset of {list(all_acceptable_ns)}, found {local_ns}")

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
                auth_ns_set = set(auth_ns)

                # Check if all authoritative nameservers are in our acceptable set
                if auth_ns_set.issubset(all_acceptable_ns):
                    delegation_result['auth_check'] = True
                    logging.info(f"[Delegation check passed] {domain}: {auth_ns}")
                else:
                    delegation_result['errors'].append(
                        f"Delegation mismatch: expected subset of {list(all_acceptable_ns)}, actual {auth_ns}")
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

def configure_global_bind_settings(dryrun, verbose):
    """Configure global BIND settings for bidirectional sync"""
    logging.info("Configuring BIND settings for bidirectional sync")
    # Implementation would go here
    pass

def refresh_domains_metadata(domains, dryrun, verbose):
    """Refresh metadata for all managed domains"""
    logging.info(f"Refreshing metadata for {len(domains)} domains")
    # Implementation would go here
    pass

def load_active_zones():
    """Load previously processed domains from file"""
    if not os.path.isfile(ACTIVE_ZONES_FILE):
        return set()
    with open(ACTIVE_ZONES_FILE) as f:
        return {line.strip().lower() for line in f if line.strip()}

def main():
    parser = argparse.ArgumentParser(description="cPanel DNS Synchronization Script")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-w', '--write', action='store_true', help='Write changes to PowerDNS (default is dry-run mode)')
    group.add_argument('-d', '--dryrun', action='store_true', help='Run in dry-run mode without making changes (default)')
    parser.add_argument('-s', '--silent', action='store_true', help='Suppress stdout logging')
    parser.add_argument('-f', '--force', action='store_true', help='Force processing of all domains')
    parser.add_argument('--orphans', action='store_true', help='Show orphaned domains')
    parser.add_argument('--no-bidirectional', dest='disable_bidirectional', action='store_true',
                       help='Disable bidirectional sync for this run')
    parser.add_argument('--cleanup', action='store_true',
                       help='Clean metadata from domains inactive for more than 30 days')
    parser.add_argument('--refresh-metadata', action='store_true',
                       help='Refresh metadata for all managed domains to ensure latest settings')
    parser.add_argument('domain', nargs='?', help='Process a single domain explicitly (optional)')
    args = parser.parse_args()

    # Default to dry-run mode if neither --write nor --dryrun is specified
    if not args.write:
        args.dryrun = True

    setup_logging(args.silent)
    single_instance()

    # Display prominent warning if in dry-run mode
    if args.dryrun:
        logging.info("=" * 80)
        logging.info("RUNNING IN DRY-RUN MODE - NO CHANGES WILL BE MADE")
        logging.info("Use --write to apply changes")
        logging.info("=" * 80)
    else:
        logging.info("=" * 80)
        logging.info("RUNNING IN WRITE MODE - CHANGES WILL BE APPLIED")
        logging.info("=" * 80)

    logging.info("Script started.")

    # Override bidirectional sync setting if specified via command line
    global ENABLE_BIDIRECTIONAL
    if args.disable_bidirectional:
        ENABLE_BIDIRECTIONAL = False
        logging.info("Bidirectional sync disabled for this run")

    # Configure global BIND settings for bidirectional sync if enabled
    if ENABLE_BIDIRECTIONAL:
        configure_global_bind_settings(args.dryrun, verbose=True)

    # Get all domains affiliated with user accounts
    affiliated_domains = get_affiliated_domains()

    # Get all DNS zones from cPanel
    cpanel_json = subprocess.getoutput('whmapi1 listzones --output=json')
    all_cpanel_zones = {z['domain'].lower().rstrip('.') for z in json.loads(cpanel_json)['data']['zone']}

    # Identify orphaned domains
    orphaned_domains = all_cpanel_zones - affiliated_domains

    if args.orphans:
        if orphaned_domains:
            logging.info(f"Found {len(orphaned_domains)} orphaned domains:")
            for domain in sorted(orphaned_domains):
                logging.info(f"  - {domain}")
        else:
            logging.info("No orphaned domains found.")

    # Active zones are only those affiliated with accounts
    active_zones = affiliated_domains
    remove_candidates = load_removal_candidates()

    # If refresh-metadata flag is set, update all domains with latest metadata settings
    if args.refresh_metadata:
        try:
            logging.info("Refreshing metadata for all managed domains")

            # Get all zones in PowerDNS
            pdns_zones_resp = requests.get(f"{PDNS_API_URL}/api/v1/servers/localhost/zones",
                                          headers={'X-API-Key': PDNS_API_KEY})
            if pdns_zones_resp.ok:
                pdns_zones = {z['name'].rstrip('.').lower() for z in pdns_zones_resp.json()}
                domains_to_refresh = pdns_zones & active_zones  # Only refresh active domains

                if domains_to_refresh:
                    logging.info(f"Found {len(domains_to_refresh)} active domains to refresh metadata")
                    refresh_domains_metadata(domains_to_refresh, args.dryrun, verbose=bool(args.domain))
                else:
                    logging.info("No active domains found to refresh metadata")
        except Exception as e:
            logging.error(f"Error during metadata refresh: {e}")

    # If cleanup flag is explicitly set, force cleanup of older inactive domains
    if args.cleanup:
        try:
            # Get all zones in PowerDNS
            pdns_zones_resp = requests.get(f"{PDNS_API_URL}/api/v1/servers/localhost/zones",
                                          headers={'X-API-Key': PDNS_API_KEY})
            if pdns_zones_resp.ok:
                pdns_zones = {z['name'].rstrip('.').lower() for z in pdns_zones_resp.json()}
                inactive_zones = pdns_zones - active_zones - EXCLUDED_DOMAINS

                if inactive_zones:
                    logging.info(f"Cleanup requested: found {len(inactive_zones)} inactive zones")
                    cleanup_inactive_domains(inactive_zones, args.dryrun, verbose=bool(args.domain))
        except Exception as e:
            logging.error(f"Error during cleanup: {e}")

    # Only process zones if not in cleanup-only mode
    if not args.cleanup or args.domain:
        # Load previously processed domains to skip unchanged ones
        previously_processed = load_active_zones() if not args.force else set()
        new_domains = affiliated_domains - previously_processed

        if new_domains:
            logging.info(f"Found {len(new_domains)} new domains to process")

        # Only process new domains if not in force mode and not processing a specific domain
        zones_to_check = {args.domain} if args.domain else (affiliated_domains if args.force else new_domains)

        for domain in zones_to_check:
            if domain in EXCLUDED_DOMAINS:
                logging.info(f"{domain} explicitly excluded.")
                continue
            if not check_authoritative_ns(domain, EXPECTED_NS):
                continue

            r = pdns_req('GET', domain)
            masters = [CPANEL_SERVER_IP, MASTERNS]

            if r.status_code == 404:
                create_pdns_zone(domain, args.dryrun, verbose=bool(args.domain))
            elif r.ok:
                zone = r.json()
                existing_masters = set(zone.get('masters', []))

                # Check all relevant metadata fields
                meta_axfr = set(next((m['content'].split(',') for m in zone.get('metadata', []) if m['kind'] == 'ALLOW-AXFR-FROM'), []))
                meta_axfr_source = next((m['content'] for m in zone.get('metadata', []) if m['kind'] == 'AXFR-SOURCE'), '')
                meta_also_notify = next((m['content'] for m in zone.get('metadata', []) if m['kind'] == 'ALSO-NOTIFY'), '')
                meta_dnssec_prevent_sync = next((m['content'] for m in zone.get('metadata', []) if m['kind'] == 'DNSSEC-PREVENT-SYNC'), '')
                meta_api_rectify = next((m['content'] for m in zone.get('metadata', []) if m['kind'] == 'API-RECTIFY'), '')
                meta_rectify_zone = next((m['content'] for m in zone.get('metadata', []) if m['kind'] == 'RECTIFY-ZONE'), '')
                meta_soa_edit_api = next((m['content'] for m in zone.get('metadata', []) if m['kind'] == 'SOA-EDIT-API'), '')

                # Check for SOA-EDIT-DNSUPDATE to remove it if present
                has_soa_edit_dnsupdate = any(m['kind'] == 'SOA-EDIT-DNSUPDATE' for m in zone.get('metadata', []))

                # Update managed-by and sync-date metadata
                needupdate = (
                    existing_masters != set([CPANEL_SERVER_IP]) or
                    meta_axfr != set([CPANEL_SERVER_IP]) or
                    zone.get('kind') != 'Native' or
                    meta_axfr_source != CPANEL_SERVER_IP or
                    meta_also_notify != CPANEL_SERVER_IP or
                    meta_dnssec_prevent_sync != '1' or
                    meta_api_rectify != '1' or
                    meta_rectify_zone != '1' or
                    meta_soa_edit_api != 'INCEPTION-INCREMENT' or
                    has_soa_edit_dnsupdate  # Need to update if SOA-EDIT-DNSUPDATE exists to remove it
                )

                if needupdate:
                    zone['masters'] = [CPANEL_SERVER_IP]  # Just cPanel as master
                    zone['kind'] = 'Native'  # Native for MySQL backend

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
                        {'kind': 'DNSSEC-PREVENT-SYNC', 'content': '1'},
                        {'kind': 'API-RECTIFY', 'content': '1'},
                        {'kind': 'RECTIFY-ZONE', 'content': '1'},
                        {'kind': 'SOA-EDIT-API', 'content': 'INCEPTION-INCREMENT'}
                        # Removed SOA-EDIT-DNSUPDATE to prevent AXFR loop
                    ]

                    # Combine preserved and new metadata
                    zone['metadata'] = preserved_metadata + new_metadata

                    update_pdns(domain, zone, args.dryrun, verbose=bool(args.domain))

        if args.write and not args.domain:
            # Save all active zones to file for future reference
            with open(ACTIVE_ZONES_FILE,'w') as f:
                for d in sorted(active_zones): f.write(f"{d}\n")
            save_removal_candidates(remove_candidates)

            # Track domains that are in PowerDNS but not in our active_zones
            # These might need to be removed if they remain inactive
            if not args.dryrun and not args.cleanup:  # Skip this if we're already doing cleanup
                try:
                    # Get all zones in PowerDNS
                    pdns_zones_resp = requests.get(f"{PDNS_API_URL}/api/v1/servers/localhost/zones",
                                                  headers={'X-API-Key': PDNS_API_KEY})
                    if pdns_zones_resp.ok:
                        pdns_zones = {z['name'].rstrip('.').lower() for z in pdns_zones_resp.json()}
                        inactive_zones = pdns_zones - active_zones - EXCLUDED_DOMAINS

                        if inactive_zones:
                            logging.info(f"Found {len(inactive_zones)} zones in PowerDNS that are no longer active")

                            # Mark domains for removal after they've been inactive for a while
                            for domain in inactive_zones:
                                if domain not in remove_candidates:
                                    remove_candidates[domain] = datetime.now().strftime("%Y-%m-%d")

                            save_removal_candidates(remove_candidates)
                except Exception as e:
                    logging.error(f"Error checking for inactive zones: {e}")

    # Log summary statistics
    processed_count = len(zones_to_check) if not args.domain else 1
    logging.info(f"Summary: Processed {processed_count} domains")
    logging.info(f"Script completed.")

if __name__ == "__main__":
    main()
