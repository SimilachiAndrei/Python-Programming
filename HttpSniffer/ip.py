"""
Module: ip

This module defines classes and utilities for handling and parsing IP packets. It provides
functionality to decode IP header fields, including source and destination addresses,
protocol, and other details.
"""

from ctypes import *
import socket
import struct


class IP(Structure):
    """
    Represents an IP packet and provides methods for parsing header fields.

    Attributes:
        ihl (int): Internet Header Length.
        version (int): IP protocol version.
        tos (int): Type of Service.
        length (int): Total length of the IP packet.
        id (int): Identification field.
        offset (int): Fragment offset.
        ttl (int): Time to Live.
        protocol (int): Protocol type.
        checksum (int): Header checksum.
        src (str): Source IP address.
        dst (str): Destination IP address.
    """
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
        """
        Creates a new instance of the IP class from a socket buffer.

        Args:
            socket_buffer (bytes): Raw socket buffer containing the IP packet.

        Returns:
            IP: An instance of the IP class.
        """

        try:
            return cls.from_buffer_copy(socket_buffer)
        except ValueError:
            return None

    def __init__(self, socket_buffer=None):
        """
        Initializes the IP packet, parsing source and destination addresses.

        Args:
            socket_buffer (bytes): Raw socket buffer containing the IP packet.
        """

        if socket_buffer:
            self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
            self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
            self.protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(self.protocol_num, str(self.protocol_num))
