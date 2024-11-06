import sys
import csv
import getpass
import warnings
import os
import logging
import argparse
import re
from collections import defaultdict

# Set up logging configuration near the top
logging.basicConfig(
    filename='script.log',  # Log output will be saved to 'script.log'
    filemode='w',           # Overwrite the log file each time the script runs
    level=logging.DEBUG,    # Set logging level to DEBUG for detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Adding FireMon package path
sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.8/site-packages')
try:
    import requests
except ImportError:
    try:
        sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.9/site-packages')
        import requests
    except ImportError:
        sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.10/site-packages')
        import requests

# Suppress warnings for unverified HTTPS requests
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Global cache for service names to avoid redundant API calls
service_name_cache = {}

# Regular expression for matching IP addresses with optional CIDR notation within strings
ip_address_pattern = re.compile(
    r'(?:^|[^0-9])'  # Start of string or a non-digit character
    r'('
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    r'(?:/\d{1,2})?'
    r')'
    r'(?:$|[^0-9])'  # End of string or a non-digit character
)

# Function to obfuscate IP addresses in data structures
def obfuscate_ip_addresses(data):
    if isinstance(data, dict):
        return {key: obfuscate_ip_addresses(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [obfuscate_ip_addresses(element) for element in data]
    elif isinstance(data, str):
        # Replace IP addresses with 'X.X.X.X' while preserving surrounding characters
        return ip_address_pattern.sub(lambda m: m.group(0).replace(m.group(1), 'X.X.X.X'), data)
    else:
        return data

# Function to authenticate and get the token
def authenticate(api_url, username, password):
    login_url = f"{api_url}/securitymanager/api/authentication/login"
    headers = {'Content-Type': 'application/json'}
    payload = {'username': username, 'password': password}
    try:
        response = requests.post(login_url, json=payload, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        logging.error("Error during authentication request: %s", e)
        sys.exit(1)
        
    if response.status_code == 200:
        try:
            token = response.json()['token']
            logging.debug("Authentication token received.")
            return token
        except KeyError:
            logging.error("Authentication succeeded but token not found in response.")
            sys.exit(1)
    else:
        logging.error("Authentication failed: %s %s", response.status_code, response.text)
        sys.exit(1)

# Function to get security rules from a device
def get_security_rules(api_url, token, device_id):
    headers = {
        'X-FM-AUTH-Token': token,
        'Content-Type': 'application/json'
    }
    query = f"device {{ id = {device_id} }}"
    url = f"{api_url}/securitymanager/api/siql/secrule/paged-search?q={query}&page=0&pageSize=1000"
    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching security rules for device ID {device_id}: %s", e)
        sys.exit(1)
    
    if response.status_code == 200:
        try:
            rules = response.json()['results']
            logging.info(f"Fetched {len(rules)} security rules for device ID {device_id}")
            return rules
        except KeyError:
            logging.error(f"Security rules fetched for device ID {device_id} but 'results' key not found in response.")
            sys.exit(1)
    else:
        logging.error(f"Failed to fetch security rules for device ID {device_id}: %s %s", response.status_code, response.text)
        sys.exit(1)

# Function to get device name by device ID
def get_device_name(api_url, token, device_id):
    headers = {
        'X-FM-AUTH-Token': token,
        'Content-Type': 'application/json'
    }
    url = f"{api_url}/securitymanager/api/domain/1/device/{device_id}"
    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching device name for device ID {device_id}: %s", e)
        return f"device_{device_id}"  # Fallback to device ID
    
    if response.status_code == 200:
        try:
            data = response.json()
            device_name = data.get('name', f"device_{device_id}")
            # Sanitize device name for file system
            device_name = "".join(c for c in device_name if c.isalnum() or c in (' ', '_', '-')).rstrip()
            logging.debug(f"Device ID {device_id} has name '{device_name}'")
            return device_name
        except KeyError:
            logging.error(f"Device name not found in response for device ID {device_id}. Using device ID as name.")
            return f"device_{device_id}"
    else:
        logging.error(f"Failed to fetch device name for device ID {device_id}: %s %s", response.status_code, response.text)
        return f"device_{device_id}"

# Function to get all devices in the domain
def get_all_devices(api_url, token):
    headers = {
        'X-FM-AUTH-Token': token,
        'Content-Type': 'application/json'
    }
    url = f"{api_url}/securitymanager/api/domain/1/device"
    all_devices = []
    page = 0
    page_size = 100
    while True:
        paged_url = f"{url}?page={page}&pageSize={page_size}"
        try:
            response = requests.get(paged_url, headers=headers, verify=False)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching devices on page {page}: %s", e)
            sys.exit(1)
        
        if response.status_code == 200:
            try:
                data = response.json()
                devices = data.get('results', [])
                if not devices:
                    break
                all_devices.extend(devices)
                logging.debug(f"Fetched {len(devices)} devices on page {page}")
                if len(devices) < page_size:
                    break
                page += 1
            except KeyError:
                logging.error("Failed to parse devices from response. 'results' key not found.")
                sys.exit(1)
        else:
            logging.error(f"Failed to fetch devices on page {page}: %s %s", response.status_code, response.text)
            sys.exit(1)
    logging.info(f"Total devices fetched: {len(all_devices)}")
    return all_devices

# Function to get devices by device group ID
def get_devices_by_group(api_url, token, group_id):
    headers = {
        'X-FM-AUTH-Token': token,
        'Content-Type': 'application/json'
    }
    query = f"devicegroup{{id={group_id}}}"
    encoded_query = requests.utils.quote(query)
    url = f"{api_url}/securitymanager/api/siql/device/paged-search?q={encoded_query}&page=0&pageSize=100&sort=name"
    all_devices = []
    page = 0
    page_size = 100
    while True:
        paged_url = f"{api_url}/securitymanager/api/siql/device/paged-search?q={encoded_query}&page={page}&pageSize={page_size}&sort=name"
        try:
            response = requests.get(paged_url, headers=headers, verify=False)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching devices in group ID {group_id} on page {page}: %s", e)
            sys.exit(1)
        
        if response.status_code == 200:
            try:
                data = response.json()
                devices = data.get('results', [])
                if not devices:
                    break
                all_devices.extend(devices)
                logging.debug(f"Fetched {len(devices)} devices in group ID {group_id} on page {page}")
                if len(devices) < page_size:
                    break
                page += 1
            except KeyError:
                logging.error(f"Failed to parse devices from response for group ID {group_id}. 'results' key not found.")
                sys.exit(1)
        else:
            logging.error(f"Failed to fetch devices in group ID {group_id} on page {page}: %s %s", response.status_code, response.text)
            sys.exit(1)
    logging.info(f"Total devices fetched in group {group_id}: {len(all_devices)}")
    return all_devices

# Function to get the FireMon Object service name by port and protocol
def get_service_name(api_url, token, protocol, port, portEnd=None, protocol_number=None):
    global service_name_cache

    # Normalize protocol
    protocol = protocol.upper()

    # Determine cache key
    if portEnd:
        cache_key = (protocol, portEnd, 'portEnd')
    elif port:
        cache_key = (protocol, port, 'port')
    elif protocol_number:
        cache_key = (protocol, protocol_number, 'protocol_number')
    else:
        cache_key = ("Unknown", "Unknown", "unknown")

    # Check if service name is already cached
    if cache_key in service_name_cache:
        return service_name_cache[cache_key]

    headers = {
        'X-FM-AUTH-Token': token,
        'Content-Type': 'application/json'
    }

    # Construct the API URL based on available parameters
    if portEnd:
        # Query by protocol type and portEnd
        url = f"{api_url}/securitymanager/api/domain/1/service?type={protocol}&useWildcardSearch=true&portEnd={portEnd}&page=0&pageSize=20&sort=name"
    elif port:
        # Query by protocol type and port
        url = f"{api_url}/securitymanager/api/domain/1/service?type={protocol}&useWildcardSearch=true&port={port}&page=0&pageSize=20&sort=name"
    elif protocol_number:
        # Query by protocol type and protocol number
        url = f"{api_url}/securitymanager/api/domain/1/service?type={protocol}&useWildcardSearch=true&protocol={protocol_number}&page=0&pageSize=20&sort=name"
    else:
        # If neither port nor protocol number is provided, return 'Unknown'
        service_name_cache[cache_key] = "Unknown"
        return "Unknown"

    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching service name for {protocol}/ {'portEnd' if portEnd else 'port'} {portEnd if portEnd else port}: %s", e)
        service_name_cache[cache_key] = f"{protocol}/{portEnd}" if portEnd else f"{protocol}/{port}"
        return service_name_cache[cache_key]
    
    if response.status_code == 200:
        data = response.json()
        if data.get('count', 0) > 0:
            try:
                service_name = data['results'][0]['name']
                service_name_cache[cache_key] = service_name
                logging.debug(f"Service name found for {protocol}/{port or portEnd or protocol_number}: {service_name}")
                return service_name
            except (KeyError, IndexError):
                service_name_cache[cache_key] = f"{protocol}/{portEnd}" if portEnd else f"{protocol}/{port}"
                logging.debug(f"No service name found, using {service_name_cache[cache_key]}")
                return service_name_cache[cache_key]
    # If no service found, fallback
    service_name_cache[cache_key] = f"{protocol}/{portEnd}" if portEnd else f"{protocol}/{port}"
    logging.debug(f"No service found in API response, using {service_name_cache[cache_key]}")
    return service_name_cache[cache_key]

# Process security rules to extract relevant data for CSV
def process_rules_to_csv(api_url, token, rules, output_file, obfuscate_ips=True):
    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        # CSV header
        writer.writerow(['Source Zone', 'Destination Zone', 'Protocol/Port', 'Protocol', 'Start Port', 'End Port', 'Service Name'])

        for index, rule in enumerate(rules):
            # Log the entire rule object
            if obfuscate_ips:
                rule_for_logging = obfuscate_ip_addresses(rule)
            else:
                rule_for_logging = rule
            logging.debug(f"Processing rule {index}: {rule_for_logging}")
            logging.debug(f"Rule keys: {list(rule.keys())}")

            # Adjust for potential nesting in the rule object
            rule_id = rule.get('id') or rule.get('ruleId') or 'Unknown'
            if rule_id == 'Unknown':
                logging.warning(f"Rule object missing 'id' key: {rule_for_logging}")
            rule_action = rule.get('action') or rule.get('ruleAction') or 'Unknown'
            if rule_action == 'Unknown':
                logging.warning(f"Rule ID {rule_id} missing 'action' key. Rule data: {rule_for_logging}")
            logging.debug(f"Processing rule ID {rule_id} with action '{rule_action}'")

            # Extract source and destination contexts
            src_context = rule.get('srcContext') or rule.get('source', {}) or {}
            dst_context = rule.get('dstContext') or rule.get('destination', {}) or {}
            src_zones = [zone.get('name', 'Unknown') for zone in src_context.get('zones', [])]
            if not src_zones:
                logging.debug(f"Rule ID {rule_id} has no source zones defined.")
                src_zones = ['Any']
            dst_zones = [zone.get('name', 'Unknown') for zone in dst_context.get('zones', [])]
            if not dst_zones:
                logging.debug(f"Rule ID {rule_id} has no destination zones defined.")
                dst_zones = ['Any']
            logging.debug(f"Rule ID {rule_id}: Source Zones: {src_zones}, Destination Zones: {dst_zones}")

            services = rule.get('services') or rule.get('serviceList') or []
            if not services:
                logging.debug(f"Rule ID {rule_id} has no services defined.")
                continue

            for service in services:
                service_entries = service.get('services', []) or service.get('serviceEntries', [])
                if not service_entries:
                    logging.debug(f"Rule ID {rule_id} has no service entries in service object.")
                    continue
                for srv in service_entries:
                    logging.debug(f"Processing service in rule ID {rule_id}: {srv}")
                    protocol = srv.get('type', 'Unknown').lower()
                    start_port = srv.get('startPort', '')
                    end_port = srv.get('endPort', '')
                    protocol_number = srv.get('protocolNumber', None)  # For cases where port is not specified

                    # Determine the port to query
                    if end_port:
                        # If end_port exists, use it for querying
                        query_port = end_port
                        portEnd = end_port
                    elif start_port:
                        # If only start_port exists, use it
                        query_port = start_port
                        portEnd = None
                    else:
                        # If neither, use protocol_number if available
                        query_port = None
                        portEnd = None

                    # Format protocol and ports
                    if start_port and end_port:
                        if start_port == end_port:
                            protocol_port = f"{protocol}/{start_port}"
                        else:
                            protocol_port = f"{protocol}/{start_port}-{end_port}"
                    elif start_port:
                        protocol_port = f"{protocol}/{start_port}"
                    else:
                        protocol_port = f"{protocol}/Any"

                    # Fetch service name using protocol and port or protocol number
                    if query_port:
                        if portEnd:
                            service_name = get_service_name(api_url, token, protocol, query_port, portEnd=portEnd)
                        elif query_port:
                            service_name = get_service_name(api_url, token, protocol, query_port)
                        else:
                            service_name = "Unknown"
                    elif protocol_number:
                        service_name = get_service_name(api_url, token, protocol, None, protocol_number=protocol_number)
                    else:
                        service_name = "Unknown"

                    for src_zone in src_zones:
                        for dst_zone in dst_zones:
                            writer.writerow([
                                src_zone,
                                dst_zone,
                                protocol_port,
                                protocol,
                                start_port if start_port else 'Any',
                                end_port if end_port else 'Any',
                                service_name
                            ])
                            logging.debug(f"Wrote CSV row for rule ID {rule_id}: {src_zone} -> {dst_zone}, {protocol_port}, {service_name}")

# Generate a matrix HTML report showing access between zones with allowed protocols and ports in the grid
def generate_html_matrix(rules, output_html, device_name, api_url, token, obfuscate_ips=True):
    zone_access = defaultdict(lambda: defaultdict(set))

    for index, rule in enumerate(rules):
        # Log the entire rule object
        if obfuscate_ips:
            rule_for_logging = obfuscate_ip_addresses(rule)
        else:
            rule_for_logging = rule
        logging.debug(f"Processing rule {index}: {rule_for_logging}")
        logging.debug(f"Rule keys: {list(rule.keys())}")

        # Adjust for potential nesting in the rule object
        rule_id = rule.get('id') or rule.get('ruleId') or 'Unknown'
        if rule_id == 'Unknown':
            logging.warning(f"Rule object missing 'id' key: {rule_for_logging}")
        rule_action = rule.get('action') or rule.get('ruleAction') or 'Unknown'
        if rule_action == 'Unknown':
            logging.warning(f"Rule ID {rule_id} missing 'action' key. Rule data: {rule_for_logging}")
        logging.debug(f"Processing rule ID {rule_id} with action '{rule_action}'")

        # Extract source and destination contexts
        src_context = rule.get('srcContext') or rule.get('source', {}) or {}
        dst_context = rule.get('dstContext') or rule.get('destination', {}) or {}
        src_zones_list = [zone.get('name', 'Unknown') for zone in src_context.get('zones', [])]
        if not src_zones_list:
            logging.debug(f"Rule ID {rule_id} has no source zones defined.")
            src_zones_list = ['Any']
        dst_zones_list = [zone.get('name', 'Unknown') for zone in dst_context.get('zones', [])]
        if not dst_zones_list:
            logging.debug(f"Rule ID {rule_id} has no destination zones defined.")
            dst_zones_list = ['Any']
        logging.debug(f"Rule ID {rule_id}: Source Zones: {src_zones_list}, Destination Zones: {dst_zones_list}")

        services = rule.get('services') or rule.get('serviceList') or []
        if not services:
            logging.debug(f"Rule ID {rule_id} has no services defined.")
            continue

        for service in services:
            service_entries = service.get('services', []) or service.get('serviceEntries', [])
            if not service_entries:
                logging.debug(f"Rule ID {rule_id} has no service entries in service object.")
                continue
            for srv in service_entries:
                logging.debug(f"Processing service in rule ID {rule_id}: {srv}")
                protocol = srv.get('type', 'Unknown').lower()
                start_port = srv.get('startPort', '')
                end_port = srv.get('endPort', '')
                protocol_number = srv.get('protocolNumber', None)  # For cases where port is not specified

                # Determine the port to query
                if end_port:
                    # If end_port exists, use it for querying
                    query_port = end_port
                    portEnd = end_port
                elif start_port:
                    # If only start_port exists, use it
                    query_port = start_port
                    portEnd = None
                else:
                    # If neither, use protocol_number if available
                    query_port = None
                    portEnd = None

                # Format protocol and ports
                if start_port and end_port:
                    if start_port == end_port:
                        protocol_port = f"{protocol}/{start_port}"
                    else:
                        protocol_port = f"{protocol}/{start_port}-{end_port}"
                elif start_port:
                    protocol_port = f"{protocol}/{start_port}"
                else:
                    protocol_port = f"{protocol}/Any"

                # Fetch service name using protocol and port or protocol number
                if query_port:
                    if portEnd:
                        service_name = get_service_name(api_url, token, protocol, query_port, portEnd=portEnd)
                    elif query_port:
                        service_name = get_service_name(api_url, token, protocol, query_port)
                    else:
                        service_name = "Unknown"
                elif protocol_number:
                    service_name = get_service_name(api_url, token, protocol, None, protocol_number=protocol_number)
                else:
                    service_name = "Unknown"

                for src_zone in src_zones_list:
                    for dst_zone in dst_zones_list:
                        zone_access[src_zone][dst_zone].add(protocol_port)
                        logging.debug(f"Added access from '{src_zone}' to '{dst_zone}' with service '{protocol_port}' in rule ID {rule_id}")

    # Collect unique zones for the matrix
    source_zones = sorted(zone_access.keys())
    destination_zones = sorted({dst for src in zone_access for dst in zone_access[src]})

    # Start building HTML content with enhanced styles and device name
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Zone Access Matrix - {device_name}</title>
    <style>
        /* Styles omitted for brevity */
    </style>
    <script>
        /* Scripts omitted for brevity */
    </script>
</head>
    <body>
        <div class="container">
            <h1>Firewall Zone Access Matrix</h1>
            <h2>Device: {device_name}</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Source Zone \ Destination Zone</th>
    """
    # Add destination zone headers
    for dst_zone in destination_zones:
        html_content += f"                            <th>{dst_zone}</th>\n"

    html_content += """                        </tr>
                    </thead>
                    <tbody>
    """
    # Add table rows for each source zone
    for src_zone in source_zones:
        html_content += f"                        <tr>\n                            <th>{src_zone}</th>\n"
        for dst_zone in destination_zones:
            protocols_ports = ', '.join(sorted(zone_access[src_zone][dst_zone])) if dst_zone in zone_access[src_zone] else "None"
            # Add data attributes for source and destination zones only
            html_content += f"                            <td data-src-zone=\"{src_zone}\" data-dst-zone=\"{dst_zone}\">{protocols_ports}</td>\n"
        html_content += "                        </tr>\n"

    # Close table and HTML tags
    html_content += """                    </tbody>
                </table>
            </div>
        </div>
    </body>
</html>
"""

    # Write the HTML content to the output file
    with open(output_html, 'w', encoding='utf-8') as file:
        file.write(html_content)
    logging.info(f"HTML matrix report generated: {output_html}")

def sanitize_filename(name):
    """Sanitize the device name to be used as a filename."""
    return "".join(c for c in name if c.isalnum() or c in (' ', '_', '-')).rstrip()

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Firewall Policy Reporting Script")
    parser.add_argument('--obfuscate-ips', action='store_true', default=True, help="Obfuscate IP addresses in logs (default: True)")
    args = parser.parse_args()

    obfuscate_ips = args.obfuscate_ips

    # Prompt user for inputs
    api_host = input("Enter FireMon host (default: https://localhost): ") or "https://localhost"
    username = input("Enter FireMon username: ")
    password = getpass.getpass("Enter FireMon password: ")

    # Device selection options
    print("\nSelect Device Selection Option:")
    print("1. Single Device ID")
    print("2. List of Device IDs (comma-separated)")
    print("3. All Devices")
    print("4. Device Group ID")
    selection = input("Enter option (1/2/3/4): ").strip()

    device_ids = []

    api_url = api_host.rstrip('/')

    # Authenticate and get token
    token = authenticate(api_url, username, password)
    logging.info("Authentication successful.")

    if selection == '1':
        device_id = input("Enter the device ID: ").strip()
        if device_id.isdigit():
            device_ids.append(device_id)
        else:
            logging.error("Invalid device ID. Must be a numeric value.")
            sys.exit(1)
    elif selection == '2':
        device_id_input = input("Enter the device IDs (comma-separated): ").strip()
        device_id_list = [id.strip() for id in device_id_input.split(',') if id.strip().isdigit()]
        if not device_id_list:
            logging.error("No valid device IDs entered.")
            sys.exit(1)
        device_ids.extend(device_id_list)
    elif selection == '3':
        logging.info("Fetching all devices...")
        devices = get_all_devices(api_url, token)
        device_ids = [str(device['id']) for device in devices]
        if not device_ids:
            logging.error("No devices found in the domain.")
            sys.exit(1)
        logging.info(f"Total devices fetched: {len(device_ids)}")
    elif selection == '4':
        group_id = input("Enter the device group ID: ").strip()
        if group_id.isdigit():
            logging.info(f"Fetching devices in group ID {group_id}...")
            devices_in_group = get_devices_by_group(api_url, token, group_id)
            device_ids = [str(device['id']) for device in devices_in_group]
            if not device_ids:
                logging.error(f"No devices found in device group ID {group_id}.")
                sys.exit(1)
            logging.info(f"Total devices fetched in group {group_id}: {len(device_ids)}")
        else:
            logging.error("Invalid device group ID. Must be a numeric value.")
            sys.exit(1)
    else:
        logging.error("Invalid selection. Please enter 1, 2, 3, or 4.")
        sys.exit(1)

    # Report generation options
    print("\nSelect Report Type to Generate:")
    print("1. CSV")
    print("2. HTML")
    print("3. Both CSV and HTML")
    report_selection = input("Enter option (1/2/3): ").strip()

    generate_csv = False
    generate_html = False

    if report_selection == '1':
        generate_csv = True
    elif report_selection == '2':
        generate_html = True
    elif report_selection == '3':
        generate_csv = True
        generate_html = True
    else:
        logging.error("Invalid selection. Please enter 1, 2, or 3.")
        sys.exit(1)

    # Create a directory to store reports
    reports_dir = 'reports'
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    # Process each device
    for device_id in device_ids:
        logging.info(f"\nProcessing Device ID: {device_id}")
        device_name = get_device_name(api_url, token, device_id)
        logging.info(f"Device Name: {device_name}")

        # Get security rules for the device
        rules = get_security_rules(api_url, token, device_id)
        logging.info(f"Number of security rules fetched for device ID {device_id}: {len(rules)}")

        # Define output file paths using device name
        sanitized_device_name = sanitize_filename(device_name).replace(' ', '_')
        OUTPUT_FILE = os.path.join(reports_dir, f'firewall_policy_services_{sanitized_device_name}.csv')
        OUTPUT_HTML = os.path.join(reports_dir, f'zone_access_matrix_{sanitized_device_name}.html')

        # Process and save rules to CSV
        if generate_csv:
            process_rules_to_csv(api_url, token, rules, OUTPUT_FILE, obfuscate_ips=obfuscate_ips)
            logging.info(f"CSV report generated: {OUTPUT_FILE}")

        # Generate HTML matrix report
        if generate_html:
            generate_html_matrix(rules, OUTPUT_HTML, device_name, api_url, token, obfuscate_ips=obfuscate_ips)
            logging.info(f"HTML report generated: {OUTPUT_HTML}")

    logging.info("\nAll selected reports have been generated successfully.")
