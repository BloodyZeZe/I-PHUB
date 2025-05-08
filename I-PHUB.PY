#!/usr/bin/env python3

import ipaddress
import socket
import subprocess
import time
import os
import sys
import platform
import re
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ASCII Art banner with animation
ASCII_BANNER = [
    "██╗      ██████╗ ██╗  ██╗██╗   ██╗██████╗ ",
    "██║      ██╔══██╗██║  ██║██║   ██║██╔══██╗",
    "██║█████╗██████╔╝███████║██║   ██║██████╔╝",
    "██║╚════╝██╔═══╝ ██╔══██║██║   ██║██╔══██╗",
    "██║      ██║     ██║  ██║╚██████╔╝██████╔╝",
    "╚═╝      ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ "
]

def clear_screen():
    """Clear the terminal screen based on OS"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_animated_banner():
    """Print the ASCII banner with a typing animation effect"""
    clear_screen()
    for line in ASCII_BANNER:
        print(Colors.CYAN + line + Colors.ENDC)
        time.sleep(0.05)
    print("\n")

def print_progress_bar(completed, total, length=50):
    """Display a progress bar for ongoing scans"""
    percent = int(100 * (completed / float(total)))
    filled_length = int(length * completed // total)
    bar = '█' * filled_length + '░' * (length - filled_length)
    sys.stdout.write(f'\r{Colors.YELLOW}Progress: |{bar}| {percent}%{Colors.ENDC}')
    sys.stdout.flush()
    if completed == total:
        print()

def get_local_ip():
    """Get the local IP address of the device"""
    try:
        # Create a socket connection to determine the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"  # Return localhost if unable to determine

def get_public_ip():
    """Get the public IP address"""
    try:
        # Use a public service to get the public IP
        public_ip = subprocess.check_output(["curl", "-s", "https://api.ipify.org"]).decode("utf-8").strip()
        return public_ip
    except Exception:
        return "Unable to determine public IP"

def get_default_gateway():
    """Get the default gateway IP address"""
    try:
        if platform.system() == "Linux":
            output = subprocess.check_output("ip route | grep default", shell=True).decode("utf-8")
            gateway = output.split()[2]
            return gateway
        else:
            return "Unknown (Non-Linux OS)"
    except Exception:
        return "Unable to determine gateway"

def scan_host(ip, port):
    """Scan a single host:port combination"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((str(ip), port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(str(ip))[0]
                except:
                    hostname = "unknown"
                
                return {
                    "ip": str(ip),
                    "port": port,
                    "status": "open",
                    "service": service,
                    "hostname": hostname
                }
    except Exception as e:
        return None
    return None

def scan_ip_range(start_ip, end_ip, ports, max_threads=100):
    """Scan a range of IP addresses for open ports"""
    print(f"{Colors.BLUE}[*] Starting scan from {start_ip} to {end_ip}{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Scanning ports: {ports}{Colors.ENDC}")
    
    # Get IP range
    ip_range = ipaddress.summarize_address_range(
        ipaddress.IPv4Address(start_ip),
        ipaddress.IPv4Address(end_ip)
    )
    
    all_ips = []
    for ipnet in ip_range:
        all_ips.extend(list(ipnet.hosts()))
    
    print(f"{Colors.BLUE}[*] Found {len(all_ips)} IP addresses to scan{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Using {max_threads} threads maximum{Colors.ENDC}")
    
    # Create tasks for scanning
    tasks = [(ip, port) for ip in all_ips for port in ports]
    total_tasks = len(tasks)
    print(f"{Colors.BLUE}[*] Total scan operations: {total_tasks}{Colors.ENDC}\n")
    
    results = []
    completed = 0
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_task = {
            executor.submit(scan_host, ip, port): (ip, port)
            for ip, port in tasks
        }
        
        for future in as_completed(future_to_task):
            ip, port = future_to_task[future]
            result = future.result()
            
            completed += 1
            print_progress_bar(completed, total_tasks)
            
            if result:
                results.append(result)
                print(f"\n{Colors.GREEN}[+] Found: {result['ip']}:{result['port']} ({result['service']}) - {result['hostname']}{Colors.ENDC}")
    
    print(f"\n{Colors.GREEN}[✓] Scan complete. {len(results)} open ports found.{Colors.ENDC}")
    return results

def analyze_ip(ip_address):
    """Analyze an IP address and determine its type and properties"""
    try:
        ip = ipaddress.ip_address(ip_address)
        
        results = {
            "ip": str(ip),
            "version": f"IPv{ip.version}",
            "is_private": ip.is_private,
            "is_global": ip.is_global,
            "is_multicast": ip.is_multicast,
            "is_reserved": ip.is_reserved,
            "is_loopback": ip.is_loopback,
            "reverse_pointer": None
        }
        
        # Try to get reverse pointer
        try:
            results["reverse_pointer"] = socket.getnameinfo((str(ip), 0), 0)[0]
        except:
            pass
        
        return results
    except ValueError:
        return None

def ping_host(ip):
    """Ping a host to check if it's alive"""
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "1", str(ip)]
        subprocess.check_output(command, stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False

def get_mac_address(ip):
    """Try to get MAC address for an IP (works only on local network)"""
    try:
        if platform.system() == "Linux":
            # Use arp to get MAC address
            result = subprocess.check_output(["arp", "-n", str(ip)]).decode("utf-8")
            mac_search = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", result)
            if mac_search:
                return mac_search.group(0)
    except:
        pass
    return "Unknown"

def check_common_services(ip, open_ports):
    """Check for common services on open ports"""
    services = {}
    
    for port_info in open_ports:
        port = port_info["port"]
        
        # HTTP/HTTPS detection
        if port in [80, 8080, 8000]:
            try:
                response = subprocess.check_output(
                    ["curl", "-s", "-m", "3", f"http://{ip}:{port}"],
                    stderr=subprocess.DEVNULL
                ).decode("utf-8", errors="ignore")
                if "<title>" in response.lower():
                    title = re.search(r"<title>(.*?)</title>", response, re.IGNORECASE)
                    if title:
                        services[port] = f"HTTP: {title.group(1)}"
            except:
                pass
        elif port == 443:
            try:
                response = subprocess.check_output(
                    ["curl", "-s", "-k", "-m", "3", f"https://{ip}:{port}"],
                    stderr=subprocess.DEVNULL
                ).decode("utf-8", errors="ignore")
                if "<title>" in response.lower():
                    title = re.search(r"<title>(.*?)</title>", response, re.IGNORECASE)
                    if title:
                        services[port] = f"HTTPS: {title.group(1)}"
            except:
                pass
    
    return services

def display_network_info():
    """Display detailed network information about the device"""
    print_animated_banner()
    print(f"{Colors.BOLD}{Colors.YELLOW}==== DETAILED NETWORK INFORMATION ===={Colors.ENDC}")
    
    # Get local IP
    local_ip = get_local_ip()
    print(f"\n{Colors.BOLD}Local IP Information:{Colors.ENDC}")
    print(f"{Colors.CYAN}IP Address: {Colors.GREEN}{local_ip}{Colors.ENDC}")
    
    # Get default gateway
    gateway = get_default_gateway()
    print(f"{Colors.CYAN}Default Gateway: {Colors.GREEN}{gateway}{Colors.ENDC}")
    
    # Get public IP
    print(f"\n{Colors.CYAN}Fetching public IP...{Colors.ENDC}")
    public_ip = get_public_ip()
    print(f"{Colors.BOLD}Public IP Information:{Colors.ENDC}")
    print(f"{Colors.CYAN}Public IP: {Colors.GREEN}{public_ip}{Colors.ENDC}")
    
    # Analyze IP addresses
    print(f"\n{Colors.BOLD}IP Analysis:{Colors.ENDC}")
    
    for ip_label, ip in [("Local IP", local_ip), ("Gateway", gateway), ("Public IP", public_ip)]:
        if ip and ip not in ["Unknown (Non-Linux OS)", "Unable to determine gateway", "Unable to determine public IP"]:
            analysis = analyze_ip(ip)
            if analysis:
                print(f"\n{Colors.YELLOW}Analysis of {ip_label} ({ip}):{Colors.ENDC}")
                print(f"  {Colors.CYAN}Type: {Colors.GREEN}{analysis['version']}{Colors.ENDC}")
                print(f"  {Colors.CYAN}Private: {Colors.GREEN}{analysis['is_private']}{Colors.ENDC}")
                print(f"  {Colors.CYAN}Global: {Colors.GREEN}{analysis['is_global']}{Colors.ENDC}")
                print(f"  {Colors.CYAN}Reserved: {Colors.GREEN}{analysis['is_reserved']}{Colors.ENDC}")
                print(f"  {Colors.CYAN}Loopback: {Colors.GREEN}{analysis['is_loopback']}{Colors.ENDC}")
                if analysis['reverse_pointer']:
                    print(f"  {Colors.CYAN}Reverse DNS: {Colors.GREEN}{analysis['reverse_pointer']}{Colors.ENDC}")
    
    input(f"\n{Colors.BOLD}{Colors.YELLOW}Press Enter to return to menu...{Colors.ENDC}")

def scan_network():
    """Perform a network scan based on user input"""
    print_animated_banner()
    print(f"{Colors.BOLD}{Colors.YELLOW}==== NETWORK SCAN ===={Colors.ENDC}")
    
    # Get local network range based on local IP
    local_ip = get_local_ip()
    ip_obj = ipaddress.IPv4Address(local_ip)
    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    
    # Default values
    start_ip = str(network.network_address + 1)
    end_ip = str(network.broadcast_address - 1)
    default_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080, 8443]
    
    # Get scan parameters from user
    print(f"\n{Colors.CYAN}Current network: {network}{Colors.ENDC}")
    
    user_start = input(f"{Colors.YELLOW}Enter start IP [{start_ip}]: {Colors.ENDC}")
    start_ip = user_start if user_start else start_ip
    
    user_end = input(f"{Colors.YELLOW}Enter end IP [{end_ip}]: {Colors.ENDC}")
    end_ip = user_end if user_end else end_ip
    
    user_ports = input(f"{Colors.YELLOW}Enter ports to scan (comma separated) [{','.join(map(str, default_ports))}]: {Colors.ENDC}")
    ports = [int(p) for p in user_ports.split(',')] if user_ports else default_ports
    
    user_threads = input(f"{Colors.YELLOW}Enter max threads [100]: {Colors.ENDC}")
    max_threads = int(user_threads) if user_threads else 100
    
    # Start scanning
    print()
    start_time = datetime.now()
    results = scan_ip_range(start_ip, end_ip, ports, max_threads)
    end_time = datetime.now()
    
    # Display results
    scan_time = end_time - start_time
    print(f"\n{Colors.BOLD}{Colors.YELLOW}==== SCAN RESULTS ===={Colors.ENDC}")
    print(f"{Colors.CYAN}Scan completed in: {Colors.GREEN}{scan_time}{Colors.ENDC}")
    print(f"{Colors.CYAN}Found {Colors.GREEN}{len(results)}{Colors.CYAN} open ports on {Colors.GREEN}{len(set(r['ip'] for r in results))}{Colors.CYAN} hosts{Colors.ENDC}")
    
    # Group results by IP
    grouped_results = {}
    for result in results:
        ip = result['ip']
        if ip not in grouped_results:
            grouped_results[ip] = []
        grouped_results[ip].append(result)
    
    # Display detailed results
    for ip, ports in grouped_results.items():
        print(f"\n{Colors.BOLD}{Colors.YELLOW}Host: {ip}{Colors.ENDC}")
        
        # Try to get MAC address
        mac = get_mac_address(ip)
        if mac != "Unknown":
            print(f"{Colors.CYAN}MAC Address: {Colors.GREEN}{mac}{Colors.ENDC}")
        
        # Try to get hostname
        hostname = ports[0]['hostname'] if ports[0]['hostname'] != "unknown" else "Unknown"
        if hostname != "Unknown":
            print(f"{Colors.CYAN}Hostname: {Colors.GREEN}{hostname}{Colors.ENDC}")
        
        # Display open ports
        print(f"{Colors.CYAN}Open ports:{Colors.ENDC}")
        for port_info in ports:
            print(f"  {Colors.GREEN}• {port_info['port']}/tcp - {port_info['service']}{Colors.ENDC}")
        
        # Check for common services
        services = check_common_services(ip, ports)
        if services:
            print(f"{Colors.CYAN}Detected services:{Colors.ENDC}")
            for port, service in services.items():
                print(f"  {Colors.GREEN}• Port {port}: {service}{Colors.ENDC}")
    
    # Save results if requested
    save_option = input(f"\n{Colors.YELLOW}Save results to file? (y/n): {Colors.ENDC}")
    if save_option.lower() == 'y':
        filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(f"Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scanned from {start_ip} to {end_ip}\n")
            f.write(f"Ports scanned: {', '.join(map(str, ports))}\n")
            f.write(f"Scan completed in: {scan_time}\n\n")
            
            for ip, ports in grouped_results.items():
                f.write(f"Host: {ip}\n")
                hostname = ports[0]['hostname'] if ports[0]['hostname'] != "unknown" else "Unknown"
                if hostname != "Unknown":
                    f.write(f"Hostname: {hostname}\n")
                
                f.write("Open ports:\n")
                for port_info in ports:
                    f.write(f"  • {port_info['port']}/tcp - {port_info['service']}\n")
                
                services = check_common_services(ip, ports)
                if services:
                    f.write("Detected services:\n")
                    for port, service in services.items():
                        f.write(f"  • Port {port}: {service}\n")
                f.write("\n")
        
        print(f"{Colors.GREEN}Results saved to {filename}{Colors.ENDC}")
    
    input(f"\n{Colors.BOLD}{Colors.YELLOW}Press Enter to return to menu...{Colors.ENDC}")

def analyze_specific_ip():
    """Analyze a specific IP address"""
    print_animated_banner()
    print(f"{Colors.BOLD}{Colors.YELLOW}==== IP ADDRESS ANALYZER ===={Colors.ENDC}")
    
    ip_address = input(f"\n{Colors.YELLOW}Enter IP address to analyze: {Colors.ENDC}")
    
    try:
        analysis = analyze_ip(ip_address)
        if not analysis:
            print(f"{Colors.RED}Invalid IP address format.{Colors.ENDC}")
            input(f"\n{Colors.BOLD}{Colors.YELLOW}Press Enter to return to menu...{Colors.ENDC}")
            return
        
        print(f"\n{Colors.BOLD}Analysis of {ip_address}:{Colors.ENDC}")
        print(f"{Colors.CYAN}IP Version: {Colors.GREEN}{analysis['version']}{Colors.ENDC}")
        print(f"{Colors.CYAN}Is Private: {Colors.GREEN}{analysis['is_private']}{Colors.ENDC}")
        print(f"{Colors.CYAN}Is Global: {Colors.GREEN}{analysis['is_global']}{Colors.ENDC}")
        print(f"{Colors.CYAN}Is Multicast: {Colors.GREEN}{analysis['is_multicast']}{Colors.ENDC}")
        print(f"{Colors.CYAN}Is Reserved: {Colors.GREEN}{analysis['is_reserved']}{Colors.ENDC}")
        print(f"{Colors.CYAN}Is Loopback: {Colors.GREEN}{analysis['is_loopback']}{Colors.ENDC}")
        
        if analysis['reverse_pointer']:
            print(f"{Colors.CYAN}Reverse DNS: {Colors.GREEN}{analysis['reverse_pointer']}{Colors.ENDC}")
        
        # Check if host is up
        print(f"\n{Colors.CYAN}Checking if host is reachable...{Colors.ENDC}")
        is_up = ping_host(ip_address)
        print(f"{Colors.CYAN}Host is {Colors.GREEN if is_up else Colors.RED}{'UP' if is_up else 'DOWN'}{Colors.ENDC}")
        
        if is_up:
            # Prompt for port scan
            scan_option = input(f"\n{Colors.YELLOW}Would you like to scan common ports? (y/n): {Colors.ENDC}")
            if scan_option.lower() == 'y':
                common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080, 8443]
                
                print(f"{Colors.CYAN}Scanning common ports...{Colors.ENDC}")
                results = []
                total_ports = len(common_ports)
                
                for i, port in enumerate(common_ports):
                    print_progress_bar(i + 1, total_ports)
                    result = scan_host(ip_address, port)
                    if result:
                        results.append(result)
                        print(f"\n{Colors.GREEN}[+] Port {port} is open ({result['service']}){Colors.ENDC}")
                
                if not results:
                    print(f"\n{Colors.YELLOW}No open ports found.{Colors.ENDC}")
                
                # Check for common services
                if results:
                    services = check_common_services(ip_address, results)
                    if services:
                        print(f"\n{Colors.CYAN}Detected services:{Colors.ENDC}")
                        for port, service in services.items():
                            print(f"{Colors.GREEN}• Port {port}: {service}{Colors.ENDC}")
    
    except Exception as e:
        print(f"{Colors.RED}Error analyzing IP: {e}{Colors.ENDC}")
    
    input(f"\n{Colors.BOLD}{Colors.YELLOW}Press Enter to return to menu...{Colors.ENDC}")

def ip_conversion_tools():
    """Tools for converting between IP formats"""
    print_animated_banner()
    print(f"{Colors.BOLD}{Colors.YELLOW}==== IP CONVERSION TOOLS ===={Colors.ENDC}")
    
    print(f"\n{Colors.CYAN}1. Convert IP to Integer{Colors.ENDC}")
    print(f"{Colors.CYAN}2. Convert Integer to IP{Colors.ENDC}")
    print(f"{Colors.CYAN}3. Convert IP to Binary{Colors.ENDC}")
    print(f"{Colors.CYAN}4. Calculate Subnet{Colors.ENDC}")
    print(f"{Colors.CYAN}5. Back to Main Menu{Colors.ENDC}")
    
    choice = input(f"\n{Colors.YELLOW}Enter your choice [1-5]: {Colors.ENDC}")
    
    if choice == '1':
        ip = input(f"\n{Colors.YELLOW}Enter IP address: {Colors.ENDC}")
        try:
            integer_value = int(ipaddress.IPv4Address(ip))
            print(f"{Colors.GREEN}Integer value: {integer_value}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.ENDC}")
    
    elif choice == '2':
        integer = input(f"\n{Colors.YELLOW}Enter integer value: {Colors.ENDC}")
        try:
            ip = str(ipaddress.IPv4Address(int(integer)))
            print(f"{Colors.GREEN}IP address: {ip}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.ENDC}")
    
    elif choice == '3':
        ip = input(f"\n{Colors.YELLOW}Enter IP address: {Colors.ENDC}")
        try:
            binary = ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])
            octets = ' '.join([binary[i:i+8] for i in range(0, len(binary), 8)])
            print(f"{Colors.GREEN}Binary: {octets}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.ENDC}")
    
    elif choice == '4':
        ip_cidr = input(f"\n{Colors.YELLOW}Enter IP address with CIDR (e.g., 192.168.1.0/24): {Colors.ENDC}")
        try:
            network = ipaddress.IPv4Network(ip_cidr, strict=False)
            print(f"{Colors.GREEN}Network: {network.network_address}{Colors.ENDC}")
            print(f"{Colors.GREEN}Broadcast: {network.broadcast_address}{Colors.ENDC}")
            print(f"{Colors.GREEN}Netmask: {network.netmask}{Colors.ENDC}")
            print(f"{Colors.GREEN}Number of hosts: {network.num_addresses - 2}{Colors.ENDC}")
            print(f"{Colors.GREEN}First host: {network.network_address + 1}{Colors.ENDC}")
            print(f"{Colors.GREEN}Last host: {network.broadcast_address - 1}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.ENDC}")
    
    elif choice == '5':
        return
    
    input(f"\n{Colors.BOLD}{Colors.YELLOW}Press Enter to return to menu...{Colors.ENDC}")

def about_tool():
    """Display information about the tool"""
    print_animated_banner()
    print(f"{Colors.BOLD}{Colors.YELLOW}==== ABOUT PRAYER IP SCANNER ===={Colors.ENDC}")
    
    print(f"\n{Colors.CYAN}PRAYER IP Scanner is an advanced network reconnaissance tool designed for Termux users.{Colors.ENDC}")
    print(f"{Colors.CYAN}Features:{Colors.ENDC}")
    print(f"{Colors.GREEN}• Comprehensive scanning of private, public, and real IPs{Colors.ENDC}")
    print(f"{Colors.GREEN}• Detailed IP analysis and classification{Colors.ENDC}")
    print(f"{Colors.GREEN}• Port scanning with service detection{Colors.ENDC}")
    print(f"{Colors.GREEN}• MAC address discovery{Colors.ENDC}")
    print(f"{Colors.GREEN}• Network information gathering{Colors.ENDC}")
    print(f"{Colors.GREEN}• IP conversion tools{Colors.ENDC}")
    
    print(f"\n{Colors.CYAN}This tool requires no ROOT permissions and is designed to work efficiently in Termux.{Colors.ENDC}")
    print(f"{Colors.CYAN}Version: 1.0{Colors.ENDC}")
    print(f"{Colors.CYAN}Created: May 8, 2025{Colors.ENDC}")
    
    # Random animation
    print(f"\n{Colors.YELLOW}Generating random animation...{Colors.ENDC}")
    time.sleep(0.5)
    
    animation_chars = [".", "o", "O", "@", "*"]
    width = 40
    height = 5
    
    for _ in range(10):
        clear_screen()
        print(f"{Colors.BOLD}{Colors.YELLOW}==== ABOUT PRAYER IP SCANNER ===={Colors.ENDC}")
        print(f"\n{Colors.CYAN}PRAYER IP Scanner - Advanced Network Tool{Colors.ENDC}")
        
        # Generate random animation frame
        for _ in range(height):
            line = ""
            for _ in range(width):
                line += random.choice(animation_chars)
            color = random.choice([Colors.RED, Colors.GREEN, Colors.BLUE, Colors.CYAN, Colors.YELLOW])
            print(color + line + Colors.ENDC)
        
        time.sleep(0.2)
    
    input(f"\n{Colors.BOLD}{Colors.YELLOW}Press Enter to return to menu...{Colors.ENDC}")

def main_menu():
    """Display the main menu and handle user choices"""
    while True:
        print_animated_banner()
        print(f"{Colors.BOLD}{Colors.YELLOW}==== MAIN MENU ===={Colors.ENDC}")
        print(f"\n{Colors.CYAN}1. Display Network Information{Colors.ENDC}")
        print(f"{Colors.CYAN}2. Scan Network{Colors.ENDC}")
        print(f"{Colors.CYAN}3. Analyze Specific IP{Colors.ENDC}")
        print(f"{Colors.CYAN}4. IP Conversion Tools{Colors.ENDC}")
        print(f"{Colors.CYAN}5. About{Colors.ENDC}")
        print(f"{Colors.CYAN}6. Exit{Colors.ENDC}")
        
        choice = input(f"\n{Colors.YELLOW}Enter your choice [1-6]: {Colors.ENDC}")
        
        if choice == '1':
            display_network_info()
        elif choice == '2':
            scan_network()
        elif choice == '3':
            analyze_specific_ip()
        elif choice == '4':
            ip_conversion_tools()
        elif choice == '5':
            about_tool()
        elif choice == '6':
            print(f"\n{Colors.GREEN}Thank you for using PRAYER IP Scanner. Goodbye!{Colors.ENDC}")
            break
        else:
            print(f"\n{Colors.RED}Invalid choice. Please try again.{Colors.ENDC}")
            time.sleep(1)

if __name__ == "__main__":
    try:
        # Display welcome animation
        print_animated_banner()
        print(f"{Colors.GREEN}Welcome to PRAYER IP Scanner!{Colors.ENDC}")
        time.sleep(1)

        # Start the application
        main_menu()

    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.ENDC}")
