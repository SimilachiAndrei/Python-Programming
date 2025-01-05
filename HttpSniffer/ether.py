"""
Module: ether

This module defines the Ethernet class, which provides a structure for parsing and
managing Ethernet frame data. It uses the ctypes library for low-level data manipulation.
"""

from ctypes import *
import socket

class Ethernet(Structure):
    """
    Represents an Ethernet frame and provides methods to parse frame components.

    Attributes:
        dst (c_ubyte * 6): Destination MAC address as an array of bytes.
        src (c_ubyte * 6): Source MAC address as an array of bytes.
        type (c_ushort): Ethernet frame type.
        dst_mac (str): Human-readable destination MAC address.
        src_mac (str): Human-readable source MAC address.
        proto (int): Protocol type in host byte order.
    """
    _fields_ = [
        ("dst", c_ubyte * 6),
        ("src", c_ubyte * 6),
        ("type", c_ushort)
    ]

    def __new__(cls, socket_buffer=None):
        """
        Creates a new instance of the Ethernet class by copying data from a socket buffer.

        Args:
            socket_buffer (bytes): Raw socket buffer containing Ethernet frame data.

        Returns:
            Ethernet: An instance of the Ethernet class.
        """
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        """
        Initializes the Ethernet frame, parsing MAC addresses and protocol type.

        Args:
            socket_buffer (bytes): Raw socket buffer containing Ethernet frame data.
        """
        self.dst_mac = ":".join(["{:02x}".format(x) for x in self.dst])
        self.src_mac = ":".join(["{:02x}".format(x) for x in self.src])
        self.proto = socket.htons(self.type)
