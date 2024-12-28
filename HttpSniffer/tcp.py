from ctypes import *
import socket


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
