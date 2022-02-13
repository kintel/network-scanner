import os
import os.path
from datetime import datetime

import configargparse
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

parser = configargparse.ArgParser()

parser.add_argument('--config', is_config_file=True, help='config')
parser.add_argument('--spreadsheet', type=str, help='Google Sheets ID')
parser.add_argument('--credentials', type=str, help='Google Sheet API credentials file')
parser.add_argument('--network', type=str, help='Network to scan (CIDR notation)')

def scan(target):
    nm = NmapProcess(target, options="-sn")
    rc = nm.run()
    if rc != 0:
        print("nmap scan failed: {0}".format(nm.stderr))
        sys.exit(1)
    try:
        parsed = NmapParser.parse(nm.stdout)
        return parsed
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))
        return None

def build_network(nmap_report):
    print(f'Started Nmap {nmap_report.version} at {nmap_report.started}')

    network = {}
    for host in nmap_report.hosts:
        if host.status == 'up' and host.mac:
            network[host.mac] = {
                'ip': host.address,
                'timestamp': datetime.fromtimestamp(nmap_report.started).isoformat(sep=' '),
            }
            if host.vendor:
                network[host.mac]['vendor'] = host.vendor
    print(nmap_report.summary)
    return network

def read_sheet(service, sheet_id):
    result = service.spreadsheets().values().get(
        spreadsheetId=sheet_id, range='Network').execute()
    rows = result.get('values', [])
    network = {row[0]: {
        'ip': row[1],
        'name': row[2],
        'type': row[3],
        'vendor': row[4],
        'timestamp': row[5] if len(row) >= 6 else None,
    } for row in rows[1:]}

    return network

def write_sheet(service, sheet_id, network):
    values = [['mac','ip','name','type','vendor','timestamp']]
    for mac,device in network.items():
        values.append([mac, device['ip'], device['name'], device['type'], device['vendor'], device['timestamp']])
    result = service.spreadsheets().values().update(spreadsheetId=sheet_id, range='Network',
                                                    valueInputOption='USER_ENTERED', body={'values': values}).execute()
    print(f'{result.get("updatedCells")} cells updated.')

def main():
    args = parser.parse_args()

    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = args.credentials
    target = args.network
    sheet_id = args.spreadsheet

    parsed = scan(target)
    new_network = build_network(parsed)
    if not new_network:
        print(f'Warning: No network hosts found. Was this executed witout sudo?')
        return

    service = build('sheets', 'v4')
    network = read_sheet(service, sheet_id)

    for mac,device in new_network.items():
        if mac in network:
            network[mac]['ip'] = device['ip']
            network[mac]['timestamp'] = device['timestamp']
            if 'vendor' in device:
                network[mac]['vendor'] = device['vendor']
        else:
            print(f'New device found: {mac} {device}')
            network[mac] = {
                'ip': device['ip'],
                'name': 'Unknown',
                'type': 'Unknown',
                'vendor': device['vendor'] if 'vendor' in device else 'Unknown',
                'timestamp': device['timestamp'],
            }
    write_sheet(service, sheet_id, network)

if __name__ == "__main__":
    main()
