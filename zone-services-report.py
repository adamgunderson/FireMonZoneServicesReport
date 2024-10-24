import sys
import csv
import getpass
import warnings
import os
from collections import defaultdict

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

# Function to authenticate and get the token
def authenticate(api_url, username, password):
    login_url = f"{api_url}/securitymanager/api/authentication/login"
    headers = {'Content-Type': 'application/json'}
    payload = {'username': username, 'password': password}
    try:
        response = requests.post(login_url, json=payload, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        print("Error during authentication request:", e)
        sys.exit(1)
        
    if response.status_code == 200:
        try:
            return response.json()['token']
        except KeyError:
            print("Authentication succeeded but token not found in response.")
            sys.exit(1)
    else:
        print("Authentication failed:", response.status_code, response.text)
        sys.exit(1)

# Function to get security rules from a device
def get_security_rules(api_url, token, device_id):
    headers = {
        'X-FM-AUTH-Token': token,
        'Content-Type': 'application/json'
    }
    query = f"device {{ id = {device_id} }}"
    url = f"{api_url}/securitymanager/api/siql/secrule/paged-search?q={query}&page=0&pageSize=100"
    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching security rules for device ID {device_id}:", e)
        sys.exit(1)
    
    if response.status_code == 200:
        try:
            return response.json()['results']
        except KeyError:
            print(f"Security rules fetched for device ID {device_id} but 'results' key not found in response.")
            sys.exit(1)
    else:
        print(f"Failed to fetch security rules for device ID {device_id}:", response.status_code, response.text)
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
        print(f"Error fetching device name for device ID {device_id}: {e}")
        return f"device_{device_id}"  # Fallback to device ID
    
    if response.status_code == 200:
        try:
            data = response.json()
            device_name = data.get('name', f"device_{device_id}")
            # Sanitize device name for file system
            device_name = "".join(c for c in device_name if c.isalnum() or c in (' ', '_', '-')).rstrip()
            return device_name
        except KeyError:
            print(f"Device name not found in response for device ID {device_id}. Using device ID as name.")
            return f"device_{device_id}"
    else:
        print(f"Failed to fetch device name for device ID {device_id}: {response.status_code} {response.text}")
        return f"device_{device_id}"

# Function to get all devices in the domain
def get_all_devices(api_url, token):
    headers = {
        'X-FM-AUTH-Token': token,
        'Content-Type': 'application/json'
    }
    # Assuming the endpoint to get all devices is as follows
    url = f"{api_url}/securitymanager/api/domain/1/device"
    all_devices = []
    page = 0
    page_size = 100
    while True:
        paged_url = f"{url}?page={page}&pageSize={page_size}"
        try:
            response = requests.get(paged_url, headers=headers, verify=False)
        except requests.exceptions.RequestException as e:
            print(f"Error fetching devices on page {page}: {e}")
            sys.exit(1)
        
        if response.status_code == 200:
            try:
                data = response.json()
                devices = data.get('results', [])
                if not devices:
                    break
                all_devices.extend(devices)
                if len(devices) < page_size:
                    break
                page += 1
            except KeyError:
                print("Failed to parse devices from response. 'results' key not found.")
                sys.exit(1)
        else:
            print(f"Failed to fetch devices on page {page}: {response.status_code} {response.text}")
            sys.exit(1)
    return all_devices

# Function to get devices by device group ID
def get_devices_by_group(api_url, token, group_id):
    headers = {
        'X-FM-AUTH-Token': token,
        'Content-Type': 'application/json'
    }
    # Encode the query parameter properly
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
            print(f"Error fetching devices in group ID {group_id} on page {page}: {e}")
            sys.exit(1)
        
        if response.status_code == 200:
            try:
                data = response.json()
                devices = data.get('results', [])
                if not devices:
                    break
                all_devices.extend(devices)
                if len(devices) < page_size:
                    break
                page += 1
            except KeyError:
                print(f"Failed to parse devices from response for group ID {group_id}. 'results' key not found.")
                sys.exit(1)
        else:
            print(f"Failed to fetch devices in group ID {group_id} on page {page}: {response.status_code} {response.text}")
            sys.exit(1)
    return all_devices

# Function to get the FireMon Object service name by port and protocol
def get_service_name(api_url, token, protocol, port, portEnd=None, protocol_number=None):
    """
    Fetches the service name from FireMon based on protocol and port.

    Parameters:
    - api_url (str): Base URL of the FireMon API.
    - token (str): Authentication token.
    - protocol (str): Protocol type (e.g., TCP, UDP, ICMP).
    - port (str): Port number as a string.
    - portEnd (str, optional): End port number as a string if the service covers a range.
    - protocol_number (int, optional): Protocol number if port is not specified.

    Returns:
    - str: Service name or a formatted protocol/port string if not found.
    """
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
        print(f"Error fetching service name for {protocol}/ {'portEnd' if portEnd else 'port'} {portEnd if portEnd else port}: {e}")
        service_name_cache[cache_key] = f"{protocol}/{portEnd}" if portEnd else f"{protocol}/{port}"
        return service_name_cache[cache_key]
    
    if response.status_code == 200:
        data = response.json()
        if data.get('count', 0) > 0:
            try:
                service_name = data['results'][0]['name']
                service_name_cache[cache_key] = service_name
                return service_name
            except (KeyError, IndexError):
                service_name_cache[cache_key] = f"{protocol}/{portEnd}" if portEnd else f"{protocol}/{port}"
                return service_name_cache[cache_key]
    # If no service found, fallback
    service_name_cache[cache_key] = f"{protocol}/{portEnd}" if portEnd else f"{protocol}/{port}"
    return service_name_cache[cache_key]

# Process security rules to extract relevant data for CSV
def process_rules_to_csv(api_url, token, rules, output_file):
    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        # CSV header
        writer.writerow(['Source Zone', 'Destination Zone', 'Protocol/Port', 'Protocol', 'Start Port', 'End Port', 'Service Name'])

        for rule in rules:
            src_context = rule.get('srcContext', {})
            dst_context = rule.get('dstContext', {})
            src_zones = [zone.get('name', 'Unknown') for zone in src_context.get('zones', [])]
            dst_zones = [zone.get('name', 'Unknown') for zone in dst_context.get('zones', [])]
            services = rule.get('services', [])

            for service in services:
                service_entries = service.get('services', [])
                for srv in service_entries:
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
                        else:
                            service_name = get_service_name(api_url, token, protocol, query_port)
                    elif protocol_number:
                        service_name = get_service_name(api_url, token, protocol, None, protocol_number=protocol_number)
                    else:
                        service_name = "Unknown"

                    writer.writerow([
                        ', '.join(src_zones) if src_zones else 'Any',
                        ', '.join(dst_zones) if dst_zones else 'Any',
                        protocol_port,
                        protocol,
                        start_port if start_port else 'Any',
                        end_port if end_port else 'Any',
                        service_name
                    ])

# Generate a matrix HTML report showing access between zones with allowed protocols and ports in the grid
def generate_html_matrix(rules, output_html, device_name, api_url, token):
    zone_access = defaultdict(lambda: defaultdict(set))
    # Removed zone_services since we no longer need to display services in the tooltip

    for rule in rules:
        src_context = rule.get('srcContext', {})
        dst_context = rule.get('dstContext', {})
        src_zones = ', '.join([zone.get('name', 'Unknown') for zone in src_context.get('zones', [])]) or 'Any'
        dst_zones = ', '.join([zone.get('name', 'Unknown') for zone in dst_context.get('zones', [])]) or 'Any'
        services = rule.get('services', [])

        for service in services:
            service_entries = service.get('services', [])
            for srv in service_entries:
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
                    else:
                        service_name = get_service_name(api_url, token, protocol, query_port)
                elif protocol_number:
                    service_name = get_service_name(api_url, token, protocol, None, protocol_number=protocol_number)
                else:
                    service_name = "Unknown"

                # Since we are removing services from the tooltip, we do not store them
                zone_access[src_zones][dst_zones].add(protocol_port)
                # No need to store service names for tooltips

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
        /* Reset some basic elements */
        body {{
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f4f6f8;
        }}
        /* Container styling */
        .container {{
            max-width: 1200px;
            margin: 40px auto;
            padding: 20px;
            background-color: #ffffff;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            border-radius: 8px;
        }}
        /* Header styling */
        h1 {{
            text-align: center;
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2em;
        }}
        h2 {{
            text-align: center;
            color: #34495e;
            margin-bottom: 30px;
            font-size: 1.5em;
            font-weight: normal;
        }}
        /* Table container */
        .table-container {{
            overflow-x: auto;
            border-radius: 8px;
        }}
        /* Table styling */
        table {{
            border-collapse: collapse;
            width: 100%;
            min-width: 800px;
            font-size: 14px;
        }}
        th, td {{
            text-align: center;
            padding: 12px 16px;
            border: 1px solid #dee2e6;
            transition: all 0.2s ease-in-out;
        }}
        th {{
            background-color: #34495e;
            color: #ecf0f1;
            position: sticky;
            top: 0;
            z-index: 2;
        }}
        tr:nth-child(even) {{
            background-color: #f9fafb;
        }}
        /* First column styling */
        th:first-child, td:first-child {{
            background-color: #2c3e50;
            color: #ecf0f1;
            position: sticky;
            left: 0;
            z-index: 1;
            border-right: 1px solid #dee2e6;
        }}
        
        /* Highlight classes */
        .cell-highlight {{
            background-color: #f1c40f !important;
            color: #2c3e50 !important;
            position: relative;
            z-index: 3;
        }}
        
        .header-highlight {{
            background-color: #e67e22 !important;
            color: white !important;
            position: relative;
            z-index: 3;
        }}
        
        .path-highlight {{
            background-color: #fff3cd !important;
            position: relative;
            z-index: 2;
        }}
        
        /* Tooltip styles */
        .tooltip {{
            position: absolute;
            background-color: rgba(44, 62, 80, 0.95);
            color: white;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 12px;
            z-index: 1000;
            pointer-events: none;
            max-width: 300px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            opacity: 0;
            transition: opacity 0.2s ease-in-out;
        }}
        
        .tooltip.show {{
            opacity: 1;
        }}
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const table = document.querySelector('table');
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip';
            document.body.appendChild(tooltip);
            
            function clearHighlights() {{
                const highlighted = table.querySelectorAll('.cell-highlight, .header-highlight, .path-highlight');
                highlighted.forEach(el => {{
                    el.classList.remove('cell-highlight', 'header-highlight', 'path-highlight');
                }});
            }}
            
            function showTooltip(cell, event) {{
                const srcZone = cell.getAttribute('data-src-zone');
                const dstZone = cell.getAttribute('data-dst-zone');
                
                if (srcZone && dstZone) {{
                    let tooltipContent = `<strong>Source Zone:</strong> ${{srcZone}}<br><strong>Destination Zone:</strong> ${{dstZone}}`;
                    
                    // Removed services from the tooltip as per the latest requirement
                    
                    tooltip.innerHTML = tooltipContent;
                    tooltip.classList.add('show');
                    
                    // Position tooltip
                    const rect = cell.getBoundingClientRect();
                    const tooltipRect = tooltip.getBoundingClientRect();
                    const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
                    const scrollLeft = window.pageXOffset || document.documentElement.scrollLeft;
                    
                    // Calculate position to avoid tooltip going off-screen
                    let top = rect.top + scrollTop - tooltipRect.height - 10;
                    let left = rect.left + scrollLeft + (rect.width / 2) - (tooltipRect.width / 2);
                    
                    // Adjust if tooltip goes beyond the top
                    if (top < scrollTop) {{
                        top = rect.bottom + scrollTop + 10; // Place below the cell
                    }}
                    
                    // Adjust if tooltip goes beyond the left
                    if (left < scrollLeft) {{
                        left = scrollLeft + 10;
                    }}
                    
                    // Adjust if tooltip goes beyond the right
                    if (left + tooltipRect.width > scrollLeft + window.innerWidth) {{
                        left = scrollLeft + window.innerWidth - tooltipRect.width - 10;
                    }}
                    
                    tooltip.style.top = `${{top}}px`;
                    tooltip.style.left = `${{left}}px`;
                }}
            }}
            
            function hideTooltip() {{
                tooltip.classList.remove('show');
            }}
            
            table.addEventListener('mouseover', function(e) {{
                const cell = e.target.closest('td');
                if (!cell) return;
                
                clearHighlights();
                
                const row = cell.parentElement;
                const rowIndex = row.rowIndex;
                const cellIndex = cell.cellIndex;
                
                // Highlight the cell
                cell.classList.add('cell-highlight');
                
                // Highlight headers
                const rowHeader = row.cells[0];
                const colHeader = table.rows[0].cells[cellIndex];
                rowHeader.classList.add('header-highlight');
                colHeader.classList.add('header-highlight');
                
                // Highlight paths
                for (let i = 1; i < cellIndex; i++) {{
                    row.cells[i].classList.add('path-highlight');
                }}
                for (let i = 1; i < rowIndex; i++) {{
                    table.rows[i].cells[cellIndex].classList.add('path-highlight');
                }}
                
                // Show tooltip
                showTooltip(cell, e);
            }});
            
            table.addEventListener('mouseout', function(e) {{
                if (!e.target.closest('td')) return;
                clearHighlights();
                hideTooltip();
            }});
            
            // Handle scroll events for tooltip
            table.addEventListener('scroll', hideTooltip);
            window.addEventListener('scroll', hideTooltip);
        }});
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
    print(f"HTML matrix report generated: {output_html}")

def sanitize_filename(name):
    """Sanitize the device name to be used as a filename."""
    return "".join(c for c in name if c.isalnum() or c in (' ', '_', '-')).rstrip()

if __name__ == "__main__":
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

    if selection == '1':
        device_id = input("Enter the device ID: ").strip()
        if device_id.isdigit():
            device_ids.append(device_id)
        else:
            print("Invalid device ID. Must be a numeric value.")
            sys.exit(1)
    elif selection == '2':
        device_id_input = input("Enter the device IDs (comma-separated): ").strip()
        device_id_list = [id.strip() for id in device_id_input.split(',') if id.strip().isdigit()]
        if not device_id_list:
            print("No valid device IDs entered.")
            sys.exit(1)
        device_ids.extend(device_id_list)
    elif selection == '3':
        print("Fetching all devices...")
        devices = get_all_devices(api_url, token)
        device_ids = [str(device['id']) for device in devices]
        if not device_ids:
            print("No devices found in the domain.")
            sys.exit(1)
        print(f"Total devices fetched: {len(device_ids)}")
    elif selection == '4':
        group_id = input("Enter the device group ID: ").strip()
        if group_id.isdigit():
            print(f"Fetching devices in group ID {group_id}...")
            devices_in_group = get_devices_by_group(api_url, token, group_id)
            device_ids = [str(device['id']) for device in devices_in_group]
            if not device_ids:
                print(f"No devices found in device group ID {group_id}.")
                sys.exit(1)
            print(f"Total devices fetched in group {group_id}: {len(device_ids)}")
        else:
            print("Invalid device group ID. Must be a numeric value.")
            sys.exit(1)
    else:
        print("Invalid selection. Please enter 1, 2, 3, or 4.")
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
        print("Invalid selection. Please enter 1, 2, or 3.")
        sys.exit(1)

    # Create a directory to store reports
    reports_dir = 'reports'
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    # Process each device
    for device_id in device_ids:
        print(f"\nProcessing Device ID: {device_id}")
        device_name = get_device_name(api_url, token, device_id)
        print(f"Device Name: {device_name}")

        # Get security rules for the device
        rules = get_security_rules(api_url, token, device_id)

        # Define output file paths using device name
        sanitized_device_name = sanitize_filename(device_name).replace(' ', '_')
        OUTPUT_FILE = os.path.join(reports_dir, f'firewall_policy_services_{sanitized_device_name}.csv')
        OUTPUT_HTML = os.path.join(reports_dir, f'zone_access_matrix_{sanitized_device_name}.html')

        # Process and save rules to CSV
        if generate_csv:
            process_rules_to_csv(api_url, token, rules, OUTPUT_FILE)
            print(f"CSV report generated: {OUTPUT_FILE}")

        # Generate HTML matrix report
        if generate_html:
            generate_html_matrix(rules, OUTPUT_HTML, device_name, api_url, token)

    print("\nAll selected reports have been generated successfully.")
