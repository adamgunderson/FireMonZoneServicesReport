# Zone Services Report
Generates reposts that identify which services are allowed between firewall zones.

## Example Usage
```
$ python3 zone-services-report.py
Enter FireMon host (default: https://localhost):
Enter FireMon username: adam
Enter FireMon password:

Select Device Selection Option:
1. Single Device ID
2. List of Device IDs (comma-separated)
3. All Devices
4. Device Group ID
Enter option (1/2/3/4): 1
Enter the device ID: 1357

Select Report Type to Generate:
1. CSV
2. HTML
3. Both CSV and HTML
Enter option (1/2/3): 3

Processing Device ID: 1357
Device Name: vSRX Live - B
CSV report generated: reports/firewall_policy_services_vSRX_Live_-_B.csv
HTML matrix report generated: reports/zone_access_matrix_vSRX_Live_-_B.html

All selected reports have been generated successfully.
```
