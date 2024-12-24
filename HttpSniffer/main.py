import gzip
import socket
import struct
from ctypes import *
from io import BytesIO

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
        self.status_code = None
        self.status_message = None
        self.headers = {}
        self.payload = None
        self.is_response = False
        self.parse_http_data()

    def __str__(self):
        output = []
        if self.is_response:
            if self.version and self.status_code and self.status_message:
                output.append(f"HTTP Response: {self.version} {self.status_code} {self.status_message}")
        else:
            if self.method and self.uri and self.version:
                output.append(f"HTTP Request: {self.method} {self.uri} {self.version}")

        if self.headers:
            output.append("Headers:")
            for key, value in self.headers.items():
                output.append(f"  {key}: {value}")

        if self.payload:
            output.append("Payload:")
            try:
                if isinstance(self.payload, bytes):
                    if 'content-encoding' in self.headers and self.headers['content-encoding'] == 'gzip':
                        try:
                            gzip_data = BytesIO(self.payload)
                            with gzip.GzipFile(fileobj=gzip_data, mode='rb') as gz:
                                decoded_payload = gz.read().decode('utf-8', errors='ignore')
                        except Exception as e:
                            decoded_payload = f"[Gzipped content - {len(self.payload)} bytes]"
                    else:
                        decoded_payload = self.payload.decode('utf-8', errors='ignore')
                else:
                    decoded_payload = str(self.payload)

                output.append(f"  {decoded_payload}")
            except Exception as e:
                output.append(f"  [Binary data - {len(self.payload)} bytes]")

        return '\n'.join(output)

    def parse_http_data(self):
        try:
            if not self.raw_data:
                return

            if not isinstance(self.raw_data, bytes):
                return

            start_index = -1
            for i in range(len(self.raw_data)):
                if self.raw_data[i:].startswith(b'HTTP/') or \
                        any(self.raw_data[i:].startswith(method.encode()) for method in
                            ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'CONNECT ', 'TRACE ', 'PATCH ']):
                    start_index = i
                    break

            if start_index == -1:
                return

            http_data = self.raw_data[start_index:]

            header_data = http_data
            try:
                header_end = header_data.find(b'\r\n\r\n')
                if header_end == -1:
                    return
                headers_bytes = header_data[:header_end]
                headers_str = headers_bytes.decode('utf-8', errors='ignore')
            except Exception as e:
                print(f"Warning: Unable to decode headers: {e}")
                return

            lines = [line.strip() for line in headers_str.split('\r\n') if line.strip()]
            if not lines:
                return

            first_line_parts = lines[0].split(' ', 2)
            if len(first_line_parts) >= 3:
                if first_line_parts[0].startswith('HTTP/'):
                    self.is_response = True
                    self.version = first_line_parts[0]
                    self.status_code = first_line_parts[1]
                    self.status_message = first_line_parts[2]
                else:
                    self.method = first_line_parts[0]
                    self.uri = first_line_parts[1]
                    self.version = first_line_parts[2]

            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    self.headers[key.lower()] = value

            payload_start = start_index + header_end + 4
            self.payload = self.raw_data[payload_start:] if payload_start < len(self.raw_data) else None

        except Exception as e:
            print(f"Warning: Error parsing HTTP data: {e}")



try:
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
                        print(http)
                        print("-" * 50)

except socket.error as e:
    print(f"Socket error: {e}")
except KeyboardInterrupt:
    print("\nExiting...")
finally:
    if 'raw_socket' in locals():
        raw_socket.close()