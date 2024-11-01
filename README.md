# Network Scanner Tool

## Overview

The **Network Scanner Tool** is a Python-based application designed to scan and enumerate devices on a local network. It utilizes ARP requests to discover active hosts within a specified IP range, providing essential details like IP address, MAC address, and the manufacturer of each device. This tool is particularly useful for network administrators and security professionals looking to manage and audit their network environments.

## Features

- **ARP Scanning**: Utilizes ARP requests to efficiently discover devices on a network.
- **Multi-threading Support**: Leverages Python's `concurrent.futures` for faster scans by scanning multiple IPs concurrently.
- **Flexible Output Formats**: Supports saving scan results in CSV or JSON formats for easy analysis and reporting.
- **Vendor Lookup**: Automatically retrieves the manufacturer of devices based on their MAC addresses using an external API.
- **Exclusion List**: Allows users to exclude specific IP addresses from scans.
- **Verbose and Color-coded Output**: Provides real-time feedback during scans with options for enhanced display.

## Requirements

- **Python 3.x**: Ensure you have Python 3 installed on your system.
- **Required Libraries**: The following Python libraries are required:
  - `scapy`
  - `argparse`
  - `csv`
  - `json`
  - `requests`
  - `tabulate`
  - `netaddr`

You can install the required libraries using pip:
```bash
pip install scapy requests tabulate netaddr
```

## Usage

To run the tool, use the following command format:

```bash
python3 network_scanner.py -t <target IP range> -o <output format> --timeout <timeout> --threads <number of threads> --verbose --exclude <ip1 ip2 ...> --color
```

### Parameters

- `-t`, `--target`: Target IP range (e.g., `10.0.2.1/24`) *(required)*
- `-o`, `--output`: Output file format (`csv` or `json`)
- `--timeout`: Timeout for ARP requests (default: `1s`)
- `--threads`: Number of threads to use for scanning (default: `10`)
- `-v`, `--verbose`: Enable verbose mode for real-time updates
- `--exclude`: IP addresses to exclude from the scan (space-separated)
- `--color`: Enable color-coded output in the terminal

### Example Command

```bash
python3 network_scanner.py -t 10.0.2.2/24 -o output.csv --timeout 2 --threads 15 --verbose --exclude 10.0.2.5 --color
```

This command scans the `10.0.2.2/24` range, saves the output to `output.csv`, uses a timeout of `2 seconds`, scans with `15 threads`, and excludes the IP `10.0.2.5` from the results, displaying them in color.

## Logging

The tool logs all scanning activities to `scan.log`, providing insights into the scanning process, any errors encountered, and the results found. Check this file for detailed records of each scan.

## Contributions

Contributions to improve the Network Scanner Tool are welcome! Feel free to submit issues, suggest features, or create pull requests to enhance the functionality of this tool.


