import socket
import struct
from ctypes import *

class Ethernet(Structure):
    _fields_ = [
        ("dst", c_ubyte * 6),
        ("src", c_ubyte * 6),
        ("type", c_ushort)
    ]

    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.dst_mac = ":".join(["{:02x}".format(x) for x in self.dst])
        self.src_mac = ":".join(["{:02x}".format(x) for x in self.src])
        self.proto = socket.htons(self.type)


class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]

    def __new__(cls, socket_buffer=None):
        try:
            return cls.from_buffer_copy(socket_buffer)
        except ValueError:
            return None

    def __init__(self, socket_buffer=None):
        if socket_buffer:
            self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
            self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
            self.protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(self.protocol_num, str(self.protocol_num))


class TCP(Structure):
    _fields_ = [
        ("sport", c_ushort),
        ("dport", c_ushort),
        ("seq", c_uint32),
        ("ack", c_uint32),
        ("offset", c_ubyte, 4),
        ("reserved", c_ubyte, 4),
        ("flags", c_ubyte),
        ("window", c_ushort),
        ("checksum", c_ushort),
        ("urgent_pointer", c_ushort)
    ]

    def __new__(cls, socket_buffer=None):
        try:
            return cls.from_buffer_copy(socket_buffer)
        except ValueError:
            return None

    def __init__(self, socket_buffer):
        if socket_buffer:
            self.sport = socket.ntohs(self.sport)
            self.dport = socket.ntohs(self.dport)


class HTTP:
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.method = None
        self.uri = None
        self.version = None
        self.headers = {}
        self.payload = None
        self.parse_http_data()

    def parse_http_data(self):
        try:
            if self.raw_data:
                data_str = self.raw_data.decode('utf-8', errors='ignore')

                parts = data_str.split('\r\n\r\n', 1)
                headers_section = parts[0]
                self.payload = parts[1] if len(parts) > 1 else None

                lines = headers_section.split('\r\n')
                if lines:
                    request_line = lines[0].split(' ')
                    if len(request_line) >= 3:
                        self.method = request_line[0]
                        self.uri = request_line[1]
                        self.version = request_line[2]

                    for line in lines[1:]:
                        if ': ' in line:
                            key, value = line.split(': ', 1)
                            self.headers[key.lower()] = value

        except Exception as e:
            print(f"Error parsing HTTP data: {e}")



try:
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    # raw_socket.bind(("wlo1",0))

    while True:
        packet, addr = raw_socket.recvfrom(256)

        ethernet_header = Ethernet(packet[:14])
        ip_header = IP(packet[14:34])

        if ip_header:
            ip_header_length = ip_header.ihl * 4
            if ip_header.protocol_num == 6:
                tcp_header = TCP(packet[14 + ip_header_length: 14 + ip_header_length + 20])
                if tcp_header and (tcp_header.sport == 80 or tcp_header.dport == 80):
                    print("Ethernet:")
                    print(f"  Source MAC: {ethernet_header.src_mac}")
                    print(f"  Destination MAC: {ethernet_header.dst_mac}")
                    print(f"  Protocol: {ethernet_header.proto}")
                    print("IP:")
                    print(f"  Source: {ip_header.src_address}")
                    print(f"  Destination: {ip_header.dst_address}")
                    print(f"  Protocol: {ip_header.protocol}")
                    print("TCP:")
                    print(f"  Source Port: {tcp_header.sport}")
                    print(f"  Destination Port: {tcp_header.dport}")
                    print("------------------------")

except socket.error as e:
    print(f"Socket error: {e}")
except KeyboardInterrupt:
    print("Exiting...")
finally:
    if 'raw_socket' in locals():
        raw_socket.close()