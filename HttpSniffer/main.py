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
