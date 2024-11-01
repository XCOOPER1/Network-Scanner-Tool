#!/usr/bin/env python

import scapy.all as scapy
import argparse
import csv
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from tabulate import tabulate
import requests
from netaddr import IPNetwork

# Configure logging to record scanning activity
logging.basicConfig(filename='scan.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def get_arguments():
    parser = argparse.ArgumentParser(description="Enhanced Network Scanner Tool")
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target IP range (e.g., 10.0.2.1/24)")
    parser.add_argument("-o", "--output", dest="output", help="Output file format (csv or json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("--timeout", type=int, default=1, help="Timeout for ARP request responses (default: 1s)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for scanning")
    parser.add_argument("--exclude", nargs='+', help="IP addresses to exclude from the scan")
    parser.add_argument("--color", action="store_true", help="Enable color-coded output")
    return parser.parse_args()

def scan(ip, timeout, verbose):
    """Performs an ARP scan on the given IP address and returns client information."""
    logging.info(f"Starting scan on IP: {ip}")
    if verbose:
        print(f"Scanning {ip}...")

    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]

        clients_list = []
        for element in answered_list:
            mac = element[1].hwsrc
            client_dict = {
                "ip": element[1].psrc,
                "mac": mac,
                "manufacturer": get_mac_vendor(mac)
            }
            clients_list.append(client_dict)
        logging.info(f"Completed scan on IP: {ip} - Found {len(clients_list)} clients.")
        return clients_list
    except Exception as e:
        logging.error(f"Error scanning IP {ip}: {e}")
        return []

def get_mac_vendor(mac):
    """Retrieves the manufacturer name for a given MAC address using an external API."""
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}")
        if response.status_code == 200:
            return response.text
        else:
            logging.warning(f"Vendor lookup failed for MAC {mac}")
            return "Unknown Vendor"
    except Exception as e:
        logging.error(f"Error retrieving vendor for MAC {mac}: {e}")
        return "Vendor Lookup Failed"

def print_result(results_list, color):
    """Displays the scanning results in a tabulated format."""
    table_data = [(client["ip"], client["mac"], client["manufacturer"]) for client in results_list]
    headers = ["IP", "MAC Address", "Manufacturer"]
    if color:
        print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
    else:
        print(tabulate(table_data, headers=headers))

def save_results(results_list, output_format):
    """Saves the scanning results to a file in the specified format (CSV or JSON)."""
    if output_format == "csv":
        with open("scan_results.csv", mode="w", newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["IP", "MAC Address", "Manufacturer"])
            for client in results_list:
                writer.writerow([client["ip"], client["mac"], client["manufacturer"]])
        logging.info("Results saved to scan_results.csv")
    elif output_format == "json":
        with open("scan_results.json", mode="w") as file:
            json.dump(results_list, file, indent=4)
        logging.info("Results saved to scan_results.json")

def threaded_scan(ip_range, timeout, threads, verbose):
    """Runs the scan on multiple IP addresses concurrently using threads."""
    ip_addresses = [str(ip) for ip in IPNetwork(ip_range)]
    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(lambda ip: scan(ip, timeout, verbose), ip_addresses)
    clients = [client for result in results for client in result]
    return clients

def main():
    options = get_arguments()
    logging.info(f"Starting scan on target: {options.target} with {options.threads} threads")

    # Perform threaded scan
    scan_result = threaded_scan(options.target, options.timeout, options.threads, options.verbose)

    # Exclude specified IPs
    if options.exclude:
        scan_result = [client for client in scan_result if client["ip"] not in options.exclude]
        logging.info(f"Excluded IPs: {', '.join(options.exclude)}")

    # Display and save results
    print_result(scan_result, options.color)
    if options.output:
        save_results(scan_result, options.output)

    logging.info(f"Scan completed on target: {options.target}. Total devices found: {len(scan_result)}")

if __name__ == "__main__":
    main()
