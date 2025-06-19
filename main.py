import socket
import struct
import argparse
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Ethernet protocol numbers (from /usr/include/linux/if_ether.h)
ETH_P_IP = 0x0800  # Internet Protocol, version 4
ETH_P_IPV6 = 0x86DD  # Internet Protocol, version 6
ETH_P_ARP = 0x0806  # Address Resolution Protocol
ETH_P_ALL = 0x0003 # All protocols

# Protocol name mapping
PROTOCOL_NAMES = {
    ETH_P_IP: "IPv4",
    ETH_P_IPV6: "IPv6",
    ETH_P_ARP: "ARP",
    ETH_P_ALL: "ALL"
}

# Global dictionary to store protocol statistics
protocol_stats = {}


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Ethernet Protocol Analyzer")
    parser.add_argument("-i", "--interface", dest="interface", default="eth0",
                        help="Network interface to capture traffic from (default: eth0)")
    parser.add_argument("-n", "--num_packets", dest="num_packets", type=int, default=100,
                        help="Number of packets to capture (default: 100)")
    parser.add_argument("-p", "--promiscuous", dest="promiscuous", action="store_true",
                        help="Enable promiscuous mode")
    parser.add_argument("-l", "--log_file", dest="log_file",
                        help="Specify the log file path (optional)")
    return parser.parse_args()


def analyze_packet(packet):
    """
    Analyzes an Ethernet packet and updates protocol statistics.

    Args:
        packet (bytes): The raw Ethernet packet data.
    """
    try:
        # Unpack the Ethernet header (14 bytes): destination MAC, source MAC, protocol type
        eth_header = struct.unpack("!6s6sH", packet[:14])
        eth_protocol = socket.ntohs(eth_header[2])  # Convert network byte order to host byte order

        # Update protocol statistics
        protocol_name = PROTOCOL_NAMES.get(eth_protocol, "Unknown")
        if protocol_name not in protocol_stats:
            protocol_stats[protocol_name] = 0
        protocol_stats[protocol_name] += 1

        logging.debug(f"Detected protocol: {protocol_name} (0x{eth_protocol:04X})")

    except struct.error as e:
        logging.error(f"Error unpacking Ethernet header: {e}")
    except Exception as e:
        logging.error(f"Error analyzing packet: {e}")


def capture_packets(interface, num_packets, promiscuous=False):
    """
    Captures network packets from the specified interface.

    Args:
        interface (str): The name of the network interface to capture from.
        num_packets (int): The number of packets to capture.
        promiscuous (bool): Whether to enable promiscuous mode.

    Returns:
        None
    """
    try:
        # Create a raw socket to capture Ethernet packets
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))

        # Bind the socket to the specified interface
        sock.bind((interface, 0))

        # Set promiscuous mode if requested
        if promiscuous:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_PROMISC, 1)
            logging.info(f"Promiscuous mode enabled on interface {interface}")
        else:
            logging.info(f"Promiscuous mode disabled on interface {interface}")


        logging.info(f"Capturing {num_packets} packets from interface {interface}...")

        for _ in range(num_packets):
            try:
                packet, _ = sock.recvfrom(65535)  # Max packet size for Ethernet
                analyze_packet(packet)
            except socket.timeout as e:
                logging.warning(f"Socket timeout: {e}")
            except OSError as e:
                logging.error(f"OS error during packet capture: {e}")
                break  # Exit capture loop on error

    except socket.error as e:
        logging.error(f"Socket error: {e}.  Ensure you have root privileges to run this tool.")
        sys.exit(1) # Exit immediately as we can't initialize the socket

    except Exception as e:
        logging.error(f"Error capturing packets: {e}")
        sys.exit(1)

def print_statistics():
    """
    Prints the collected protocol statistics.
    """
    print("\nProtocol Statistics:")
    for protocol, count in protocol_stats.items():
        print(f"- {protocol}: {count}")

def main():
    """
    Main function to execute the Ethernet protocol analyzer.
    """
    args = setup_argparse()

    # Configure logging to file if specified
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setLevel(logging.DEBUG)  # Log everything to file
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logging.getLogger('').addHandler(file_handler)
        logging.info(f"Logging to file: {args.log_file}")


    try:
        capture_packets(args.interface, args.num_packets, args.promiscuous)
        print_statistics()

    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
        print_statistics()
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        logging.info("Exiting Ethernet Protocol Analyzer.")

if __name__ == "__main__":
    main()


# Usage Examples:
#
# 1.  Capture 100 packets from the default interface (eth0) and print statistics:
#     python net_ethernet_protocol_analyzer.py
#
# 2.  Capture 200 packets from interface wlan0:
#     python net_ethernet_protocol_analyzer.py -i wlan0 -n 200
#
# 3.  Capture packets in promiscuous mode from interface eth0:
#     python net_ethernet_protocol_analyzer.py -i eth0 -p
#
# 4.  Capture 500 packets from interface eth0 and log the output to a file named analyzer.log:
#     python net_ethernet_protocol_analyzer.py -i eth0 -n 500 -l analyzer.log
#
# Offensive Tool Consideration:
#
# The script itself is primarily a passive analysis tool.  However, by capturing network traffic, an attacker
# could potentially gather information about network protocols being used, identify vulnerable services,
# or intercept sensitive data if the network traffic is not encrypted. Enabling promiscuous mode increases the
# amount of traffic captured, including traffic not specifically destined for the capturing host, which could
# reveal more information about the network. Mitigation strategies include using network encryption (e.g., HTTPS,
# SSH, VPN), implementing proper access controls, and monitoring network traffic for suspicious activity. The tool
# requires root privileges to run, which could be a risk if the tool itself contains vulnerabilities.