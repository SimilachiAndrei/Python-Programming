import socket
import sys
from ether import Ethernet
from tcp import TCP
from ip import IP
from http import HTTP
from storage import RequestStorage
import threading

from ui import UI


def parse_filters():
    filters = {}
    i = 1
    while i < len(sys.argv):
        if i + 1 < len(sys.argv):
            if sys.argv[i] == "-ip":
                filters["ip"] = sys.argv[i + 1]
            elif sys.argv[i] == "-method":
                filters["method"] = sys.argv[i + 1].upper()
            elif sys.argv[i] == "-port":
                filters["port"] = int(sys.argv[i + 1])
            elif sys.argv[i] == "-type":
                filters["type"] = sys.argv[i + 1].upper()
            i += 2
        else:
            i += 1
    return filters


def apply_filters(filters, eth_header, ip_header, tcp_header, http_header):
    if not filters:
        return True

    for filter in filters:
        if filter == "ip":
            if ip_header.src_address != filters[filter]:
                return False
        elif filter == "port":
            if tcp_header.sport != filters[filter]:
                return False
        elif filter == "method":
            if http_header.method != filters[filter]:
                return False
        elif filter == "type":
            if http_header.is_response and filters[filter] == "REQUEST":
                return False
            if not http_header.is_response and filters[filter] == "RESPONSE":
                return False

    return True


request_store = RequestStorage()
ui = UI(request_store)
ui_thread = threading.Thread(target=ui.start)
ui_thread.start()

try:
    filters = parse_filters()
    print(f"Applied filters: {filters}")

    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("Listening for HTTP packets... Press Ctrl+C to stop.")

    while True:
        packet, addr = raw_socket.recvfrom(65535)
        ethernet_header = Ethernet(packet[:14])
        ip_header = IP(packet[14:34])

        if ip_header and ip_header.protocol_num == 6:
            ip_header_length = ip_header.ihl * 4
            tcp_header = TCP(packet[14 + ip_header_length:14 + ip_header_length + 20])

            if tcp_header and (tcp_header.sport == 80 or tcp_header.dport == 80):
                payload_offset = 14 + ip_header_length + (tcp_header.offset * 4)
                payload = packet[payload_offset:]

                if payload:
                    http = HTTP(payload)
                    if http.headers:
                        if apply_filters(filters, ethernet_header, ip_header, tcp_header, http):
                            request_data = {
                                'ethernet': ethernet_header,
                                'ip': ip_header,
                                'tcp': tcp_header,
                                'http': http
                            }
                            idx = request_store.add_request(request_data)
                            print(f"\nNew request captured (#{idx})")

except socket.error as e:
    print(f"Socket error: {e}")
except KeyboardInterrupt:
    print("\nExiting...")
finally:
    if 'raw_socket' in locals():
        raw_socket.close()
