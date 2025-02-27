import argparse
import logging
from datetime import datetime
import socket

from scapy.all import sniff, rdpcap, TCP, UDP, DNS, IP

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(pastime)s [%(levelness)s]: %(message)s",
    handlers=[logging.StreamHandler()],
)


def validate_interface(interface):
    """
    Validate if a specified network interface exists.
    """
    try:
        all_interfaces = [iface[1] for iface in socket.if_nameindex()]
        if interface not in all_interfaces:
            logging.error(
                f"Interface '{interface}' does not exist. Available interfaces: {', '.join(all_interfaces)}"
            )
            return False
        return True
    except Exception as e:
        logging.error(f"Error validating interface '{interface}': {e}")
        return False


def get_default_interface():
    """
    Attempt to get a default network interface. If unavailable, return None.
    """
    try:
        interfaces = socket.if_nameindex()
        if interfaces:
            return interfaces[0][1]
    except Exception as e:
        logging.warning(f"Unable to fetch default interface: {e}")
    return None


def packet_callback(packet):
    """
    Process and analyze captured packets for key details.
    Handles IP, TCP, UDP, and DNS protocols, printing relevant information.
    """
    try:
        logging.info(f"Packet Captured - Timestamp: {datetime.now()}")

        # Handle IP packets
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ttl = packet[IP].ttl
            logging.info(f"IP Packet - Source: {src_ip}, Destination: {dst_ip}, TTL: {ttl}")
        else:
            logging.warning("Non-IP packet detected. Skipping further analysis.")
            return

        # Handle TCP packets
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            logging.info(f"TCP Packet - Source Port: {sport}, Destination Port: {dport}, Flags: {flags}")

        # Handle UDP packets
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            logging.info(f"UDP Packet - Source Port: {sport}, Destination Port: {dport}")

        # Handle DNS packets
        if DNS in packet:
            if packet[DNS].qd:  # DNS Queries
                try:
                    query_name = packet[DNS].qd.qname.decode("utf-8", errors="ignore")
                    logging.info(f"DNS Query - Domain: {query_name}")
                except Exception as e:
                    logging.error(f"Error decoding DNS query name: {e}")

            if packet[DNS].an:  # DNS Responses
                try:
                    for i in range(len(packet[DNS].an)):
                        rrname = packet[DNS].an[i].rrname.decode("utf-8", errors="ignore")
                        rdata = packet[DNS].an[i].rdata
                        logging.info(f"DNS Response - {rrname} -> {rdata}")
                except (IndexError, AttributeError, UnicodeDecodeError) as e:
                    logging.warning(f"Error processing DNS response: {e}")

        # Detect unusual protocol numbers (for non-TCP/UDP traffic)
        if IP in packet and packet[IP].proto not in [6, 17]:  # 6 = TCP, 17 = UDP
            unknown_proto = packet[IP].proto
            logging.warning(f"Unknown Protocol Detected - Protocol Number: {unknown_proto}")
            logging.info(
                "This packet uses a transport-layer protocol that is currently unsupported for detailed analysis."
            )

    except Exception as e:
        logging.error(f"Error processing packet: {e}")


def capture_live_packets(interface, packet_count, packet_filter):
    """
    Capture live packets on the specified network interface.
    """
    if not validate_interface(interface):
        logging.error("Invalid interface specified. Exiting...")
        exit(1)

    logging.info(f"Starting packet capture on interface '{interface}' with filter: {packet_filter}")
    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            filter=packet_filter,
            count=packet_count,
        )
        logging.info("Packet capture complete.")
    except Exception as e:
        logging.error(f"Error during packet capture: {e}")
        exit(1)


def analyze_pcap_file(pcap_file):
    """
    Analyze a given PCAP file and process packets.
    """
    logging.info(f"Reading packets from PCAP file: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
        for packet in packets:
            packet_callback(packet)
        logging.info("PCAP file analysis complete.")
    except FileNotFoundError:
        logging.error(f"PCAP file '{pcap_file}' not found.")
    except Exception as e:
        logging.error(f"Error reading PCAP file: {e}")


def main():
    parser = argparse.ArgumentParser(description="Advanced Packet Analysis Tool")

    # Mutual exclusivity between live traffic and PCAP analysis
    live_or_pcap_group = parser.add_mutually_exclusive_group(required=True)
    live_or_pcap_group.add_argument("--live", action="store_true", help="Capture live traffic")
    live_or_pcap_group.add_argument("--pcap", type=str, help="Provide a PCAP file for offline analysis")

    # Arguments common to live capture
    parser.add_argument(
        "--interface",
        type=str,
        dest="interface",
        default="",
        help="Network interface for live capture. Leave blank to auto-detect.",
    )
    parser.add_argument(
        "--count",
        type=int,
        choices=range(1, 10001),
        default=10,
        dest="count",
        help="Number of packets to capture (default: 10, range: 1-10,000)",
    )
    parser.add_argument(
        "--filter",
        type=str,
        dest="filter",
        default="ip",
        help="BPF filter for packet filtering (default: 'ip')",
    )

    args = parser.parse_args()

    # Handle Live Packet Capture
    if args.live:
        logging.info("Live mode specified.")
        interface = args.interface or get_default_interface()
        if not interface:
            logging.error("No valid network interface specified or available.")
            exit(1)
        capture_live_packets(interface, args.count, args.filter)

    # Handle PCAP File Analysis
    elif args.pcap:
        logging.info("PCAP analysis mode specified.")
        analyze_pcap_file(args.pcap)





    
