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
    def __init__(self):
        self.filters = self.parse_filters()
        self.request_store = RequestStorage()
        self.ui = UI(self.request_store)
        self.raw_socket = None

    def parse_filters(self):
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
        ui_thread = threading.Thread(target=self.ui.start)
        ui_thread.daemon = True
        ui_thread.start()

    def initialize_socket(self):
        self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("Listening for HTTP packets... Press Ctrl+C to stop.")

    def process_packet(self, packet):
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


if __name__ == "__main__":
    sniffer = PacketSniffer()
    sniffer.start_ui()
    sniffer.run()