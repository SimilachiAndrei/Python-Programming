"""
Module: storage

This module provides utilities for saving and retrieving captured packets to and from
persistent storage. It supports simple storage mechanisms such as files.
"""
from collections import deque
import threading


class RequestStorage:
    """A thread-safe storage system for managing network requests.

    This class implements a fixed-size circular buffer using collections.deque
    to store network request data. It provides thread-safe operations for adding,
    retrieving, and listing requests.

    Attributes:
        requests (collections.deque): A thread-safe double-ended queue storing request data.
        request_lock (threading.Lock): A threading lock for thread-safe operations.

    Args:
        max_size (int, optional): Maximum number of requests to store. Defaults to 100.
            When exceeded, oldest requests are automatically removed.
    """
    def __init__(self, max_size=100):
        """Initialize a new RequestStorage instance.

        Args:
            max_size (int, optional): Maximum number of requests to store. Defaults to 100.
        """
        self.requests = deque(maxlen=max_size)
        self.request_lock = threading.Lock()

    def add_request(self, request_data):
        """Add a new request to the storage.

        This method is thread-safe and will add the request to the end of the deque.
        If the deque is at maximum capacity, the oldest request will be removed.

        Args:
            request_data: The request data to store. Can be of any type.

        Returns:
            int: The index where the request was stored.
        """
        with self.request_lock:
            self.requests.append(request_data)
            return len(self.requests) - 1

    def get_request(self, index):
        """Retrieve a request by its index.

        This method is thread-safe and will return the request at the specified index
        if it exists.

        Args:
            index (int): The index of the request to retrieve.

        Returns:
            The request data if found, None otherwise.
        """
        with self.request_lock:
            if 0 <= index < len(self.requests):
                return self.requests[index]
            return None

    def list_requests(self):
        """List all stored requests with their indices.

        This method is thread-safe and returns a list of tuples containing
        the index and request data for all stored requests.

        Returns:
            list: A list of tuples (index, request_data) for all stored requests.
        """
        with self.request_lock:
            return list(enumerate(self.requests))