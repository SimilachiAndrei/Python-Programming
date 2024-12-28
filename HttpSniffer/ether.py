from ctypes import *
import socket


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
