"""
Module: packet_sniffer

This module implements a network packet sniffer specifically designed to capture and analyze
HTTP traffic. It provides functionality for filtering packets based on various criteria
and displaying captured packets through a user interface.

The sniffer operates at the raw socket level and can decode multiple protocol layers
including Ethernet, IP, TCP, and HTTP.

Example:
    sniffer = PacketSniffer()
    sniffer.start_ui()
    sniffer.run()

Command-line Arguments:
    -ip VALUE      Filter packets by source IP address
    -method VALUE  Filter packets by HTTP method (GET, POST, etc.)
    -port VALUE    Filter packets by source port
    -type VALUE    Filter packets by type (REQUEST or RESPONSE)
"""
import socket
import sys
import threading

from ether import Ethernet
from tcp import TCP
from ip import IP
from http import HTTP
from storage import RequestStorage
from ui import UI


class PacketSniffer:
    """A network packet sniffer for capturing and analyzing HTTP traffic.

    This class provides functionality to capture network packets at the raw socket level,
    decode various protocol layers, and filter packets based on user-specified criteria.

    Attributes:
        filters (dict): Dictionary of active filters for packet capturing
        request_store (RequestStorage): Storage for captured packets
        ui (UI): User interface instance for displaying captured packets
        raw_socket (socket): Raw network socket for packet capture
    """
    def __init__(self):
        """Initialize the PacketSniffer with filters, storage, and UI components."""
        self.filters = self.parse_filters()
        self.request_store = RequestStorage()
        self.ui = UI(self.request_store)
        self.raw_socket = None

    def parse_filters(self):
        """Parse command-line arguments to extract packet filters.

        Returns:
            dict: Dictionary containing filter criteria parsed from command-line arguments.
                 Possible keys: 'ip', 'method', 'port', 'type'
        """
        filters = {}
        i = 1
        while i < len(sys.argv):
            if i + 1 < len(sys.argv):
                flag, value = sys.argv[i], sys.argv[i + 1]
                if flag == "-ip":
                    filters["ip"] = value
                elif flag == "-method":
                    filters["method"] = value.upper()
                elif flag == "-port":
                    filters["port"] = int(value)
                elif flag == "-type":
                    filters["type"] = value.upper()
                i += 2
            else:
                i += 1
        return filters

    def apply_filters(cls,filters, eth_header, ip_header, tcp_header, http_header):
        """Apply filters to a packet to determine if it should be captured.

        Args:
            filters (dict): Dictionary of filter criteria
            eth_header (Ethernet): Ethernet header object
            ip_header (IP): IP header object
            tcp_header (TCP): TCP header object
            http_header (HTTP): HTTP header object

        Returns:
            bool: True if packet matches all filters, False otherwise
        """
        if not filters:
            return True

        for filter_key, filter_value in filters.items():
            if filter_key == "ip" and ip_header.src_address != filter_value:
                return False
            elif filter_key == "port" and tcp_header.sport != filter_value:
                return False
            elif filter_key == "method" and http_header.method != filter_value:
                return False
            elif filter_key == "type":
                is_request = not http_header.is_response
                if (filter_value == "REQUEST" and not is_request) or \
                   (filter_value == "RESPONSE" and is_request):
                    return False

        return True

    def start_ui(self):
        """Start the user interface in a separate daemon thread."""
        ui_thread = threading.Thread(target=self.ui.start)
        ui_thread.daemon = True
        ui_thread.start()

    def initialize_socket(self):
        """Initialize the raw network socket for packet capture."""
        self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("Listening for HTTP packets... Press Ctrl+C to stop.")

    def process_packet(self, packet):
        """Process a captured network packet.

        This method decodes the various protocol layers of the packet and,
        if it matches the specified filters, stores it in the request store.

        Args:
            packet (bytes): Raw packet data

        Raises:
            Exception: If there's an error processing the packet
        """
        try:
            ethernet_header = Ethernet(packet[:14])
            ip_header = IP(packet[14:34])

            if ip_header and ip_header.protocol_num == 6:
                ip_header_length = ip_header.ihl * 4
                tcp_header = TCP(packet[14 + ip_header_length:14 + ip_header_length + 20])

                if tcp_header and (tcp_header.sport == 80 or tcp_header.dport == 80):
                    payload_offset = 14 + ip_header_length + (tcp_header.offset * 4)
                    payload = packet[payload_offset:]

                    if payload:
                        http_header = HTTP(payload)
                        if http_header.headers:
                            if self.apply_filters(self.filters, ethernet_header, ip_header, tcp_header, http_header):
                                request_data = {
                                    'ethernet': ethernet_header,
                                    'ip': ip_header,
                                    'tcp': tcp_header,
                                    'http': http_header
                                }
                                idx = self.request_store.add_request(request_data)
                                print(f"\nNew request captured (#{idx})")
        except Exception as e:
            print(f"Error processing packet: {e}")

    def run(self):
        """Start the packet capture process.

        This method initializes the socket and begins capturing packets.
        It continues until interrupted by the user (Ctrl+C).

        Raises:
            socket.error: If there's an error with the network socket
            KeyboardInterrupt: If the user interrupts the capture process
        """
        try:
            self.initialize_socket()
            print(f"Applied filters: {self.filters}")
            while True:
                packet, _ = self.raw_socket.recvfrom(65535)
                self.process_packet(packet)
        except socket.error as e:
            print(f"Socket error: {e}")
        except KeyboardInterrupt:
            print("\nExiting...")
        finally:
            if self.raw_socket:
                self.raw_socket.close()


sniffer = PacketSniffer()
sniffer.start_ui()
sniffer.run()