import socket
import requests
from nmap import PortScanner

# Function to scan open ports using socket
def scan_open_ports(host, start_port, end_port):
    print(f"Scanning open ports on {host} from {start_port} to {end_port}")
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Function to check for outdated software versions
def check_outdated_software(url):
    try:
        response = requests.get(url)
        server = response.headers.get('Server', 'Unknown')
        if server != 'Unknown':
            print(f"Server software: {server}")
            # Add logic here to compare server version with known vulnerabilities database
        else:
            print("Server software information not available")
    except Exception as e:
        print(f"Error connecting to {url}: {e}")

# Function to check for common misconfigurations
def check_misconfigurations(url):
    try:
        response = requests.get(url)
        if 'X-Frame-Options' not in response.headers:
            print("Missing X-Frame-Options header")
        if 'X-Content-Type-Options' not in response.headers:
            print("Missing X-Content-Type-Options header")
        if 'Content-Security-Policy' not in response.headers:
            print("Missing Content-Security-Policy header")
    except Exception as e:
        print(f"Error connecting to {url}: {e}")

# Function to perform a full network scan using nmap
def network_scan(host):
    scanner = PortScanner()
    print(f"Performing network scan on {host}")
    scanner.scan(host, arguments='-sS')
    for host in scanner.all_hosts():
        print(f'Host : {host} ({scanner[host].hostname()})')
        print(f'State : {scanner[host].state()}')
        for protocol in scanner[host].all_protocols():
            print(f'Protocol : {protocol}')
            ports = scanner[host][protocol].keys()
            for port in ports:
                print(f'Port : {port}\tState : {scanner[host][protocol][port]["state"]}')

if __name__ == "__main__":
    target_host = 'example.com'  # Replace with target host
    target_url = 'http://example.com'  # Replace with target URL
    
    # Scan open ports
    open_ports = scan_open_ports(target_host, 1, 1024)
    print(f"Open ports: {open_ports}")
    
    # Check for outdated software
    check_outdated_software(target_url)
    
    # Check for common misconfigurations
    check_misconfigurations(target_url)
    
    # Perform a network scan using nmap
    network_scan(target_host)
