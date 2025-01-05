"""
Module: http

This module defines the HTTP class, which provides utilities for parsing and handling
HTTP requests and responses. It supports parsing headers, methods, URIs, and payloads.
"""
import gzip
from io import BytesIO

class HTTP:
    """
    Represents an HTTP message, capable of parsing both requests and responses.

    Attributes:
        raw_data (bytes): The raw HTTP message as received.
        method (str): The HTTP method (e.g., GET, POST) for requests.
        uri (str): The requested URI for requests.
        version (str): The HTTP version (e.g., HTTP/1.1).
        status_code (int): The status code for responses.
        status_message (str): The status message for responses.
        headers (dict): A dictionary of HTTP headers.
        payload (bytes): The body of the HTTP message.
        is_response (bool): Indicates if the message is a response.
    """

    def __init__(self, raw_data):
        """
        Initializes the HTTP object by parsing the raw HTTP data.

        Args:
            raw_data (bytes): The raw HTTP message to be parsed.
        """
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
        """
        Returns a string representation of the HTTP message, including headers and payload.

        Returns:
            str: A human-readable representation of the HTTP message.
        """

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
        """
        Parses the raw HTTP data to populate the object's attributes.

        This method identifies if the data is a request or response and extracts
        headers, method, URI, status code, status message, and payload.
        """

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