"""
Module: tcp

This module provides structures and utilities for parsing TCP headers. It enables decoding
of essential fields such as source and destination ports, sequence numbers, and flags.
"""
from ctypes import *
import socket


class TCP(Structure):
    """
    Represents a TCP segment and provides methods for parsing header fields.

    Attributes:
        src_port (int): Source port number.
        dst_port (int): Destination port number.
        sequence (int): Sequence number.
        acknowledgment (int): Acknowledgment number.
        offset_reserved (int): Offset and reserved bits.
        flags (int): TCP flags.
        window (int): Window size.
        checksum (int): Header checksum.
        urgent_pointer (int): Urgent pointer.
    """
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
        """
        Creates a new instance of the TCP class from a socket buffer.

        Args:
            socket_buffer (bytes): Raw socket buffer containing the TCP segment.

        Returns:
            TCP: An instance of the TCP class.
        """
        try:
            return cls.from_buffer_copy(socket_buffer)
        except ValueError:
            return None

    def __init__(self, socket_buffer):
        """
        Initializes the TCP segment, parsing key header fields.

        Args:
            socket_buffer (bytes): Raw socket buffer containing the TCP segment.
        """

        if socket_buffer:
            self.sport = socket.ntohs(self.sport)
            self.dport = socket.ntohs(self.dport)
