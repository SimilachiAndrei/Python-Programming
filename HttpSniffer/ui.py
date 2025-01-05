"""
Module: ui

This module provides a command-line user interface for interacting with captured network
requests. It allows users to view and analyze network packet information at various
protocol layers.
"""
from io import BytesIO
import gzip
import sys

class UI:
    """A command-line interface for interacting with captured network requests.

    This class provides an interactive menu-driven interface for viewing and analyzing
    network packets, including details about Ethernet, IP, TCP, and HTTP layers.

    Attributes:
        request_store (RequestStorage): An instance of RequestStorage containing captured requests.
    """

    def __init__(self, request_store):
        """Initialize the UI with a request storage instance.

        Args:
            request_store (RequestStorage): The storage system containing captured requests.
        """
        self.request_store = request_store

    def start(self):
        """Start the interactive command-line interface.

        Continuously displays the menu and handles user input until the program is exited.
        Handles various exceptions to prevent program crashes.
        """
        while True:
            try:
                self.display_menu()
                choice = input()
                self.handle_choice(choice)
            except ValueError as e:
                print(f"Invalid input: {e}")
            except Exception as e:
                print(f"Error: {e}")

    def display_menu(self):
        """Display the main menu options to the user."""
        print("\nCommands:")
        print("1. List all captured requests")
        print("2. View request details")
        print("3. Exit program")

    def handle_choice(self, choice):
        """Process the user's menu selection.

        Args:
            choice (str): The user's input choice from the menu.
        """
        if choice == "1":
            self.list_requests()
        elif choice == "2":
            self.view_request_details()
        elif choice == "3":
            sys.exit(0)
        else:
            print("Invalid choice!")

    def list_requests(self):
        """Display a list of all captured requests with basic information."""
        requests = self.request_store.list_requests()
        print("\nCaptured Requests:")
        for idx, req in requests:
            if req['http'].is_response:
                print(f"{idx}. Response: {req['http'].status_code} from {req['ip'].src_address}")
            else:
                print(f"{idx}. {req['http'].method} to {req['ip'].dst_address}")

    def view_request_details(self):
        """Handle the detailed view of a specific request.

        Prompts user for request index and detail options, then displays selected information.
        """
        idx = int(input("Enter request number: "))
        request = self.request_store.get_request(idx)
        if request:
            self.display_detail_options()
            view_choice = input("\nEnter your choices (e.g., 1,3,4): ")
            choices = [c.strip() for c in view_choice.split(',')]
            self.display_selected_details(request, choices)
        else:
            print("Request not found!")

    def display_detail_options(self):
        """Display available detail viewing options."""
        print("\nChoose what information to view (comma-separated):")
        print("1. Ethernet")
        print("2. IP")
        print("3. TCP")
        print("4. HTTP Headers")
        print("5. HTTP Payload")
        print("6. All")

    def display_selected_details(self, request, choices):
        """Display the selected details for a request.

        Args:
            request (dict): The request data containing all protocol layers.
            choices (list): List of strings representing user's detail choices.
        """
        print("\nDetailed Request Information:")

        if '6' in choices or '1' in choices:
            self.display_ethernet_info(request)

        if '6' in choices or '2' in choices:
            self.display_ip_info(request)

        if '6' in choices or '3' in choices:
            self.display_tcp_info(request)

        if '6' in choices or '4' in choices:
            self.display_http_headers(request)

        if '6' in choices or '5' in choices:
            self.display_http_payload(request)

    def display_ethernet_info(self, request):
        """Display Ethernet layer information.

        Args:
            request (dict): The request data containing Ethernet information.
        """
        print("\nEthernet Layer:")
        print(f"  Source MAC: {request['ethernet'].src_mac}")
        print(f"  Destination MAC: {request['ethernet'].dst_mac}")

    def display_ip_info(self, request):
        """Display IP layer information.

        Args:
            request (dict): The request data containing IP information.
        """
        print("\nIP Layer:")
        print(f"  Source IP: {request['ip'].src_address}")
        print(f"  Destination IP: {request['ip'].dst_address}")
        print(f"  Protocol: {request['ip'].protocol}")

    def display_tcp_info(self, request):
        """Display TCP layer information.

        Args:
            request (dict): The request data containing TCP information.
        """
        print("\nTCP Layer:")
        print(f"  Source Port: {request['tcp'].sport}")
        print(f"  Destination Port: {request['tcp'].dport}")

    def display_http_headers(self, request):
        """Display HTTP headers information.

        Args:
            request (dict): The request data containing HTTP header information.
        """
        print("\nHTTP Headers:")
        if request['http'].is_response:
            print(f"  Status: {request['http'].version} {request['http'].status_code} {request['http'].status_message}")
        else:
            print(f"  Request: {request['http'].method} {request['http'].uri} {request['http'].version}")

        for key, value in request['http'].headers.items():
            print(f"  {key}: {value}")

    def display_http_payload(self, request):
        """Display HTTP payload information.

        Args:
            request (dict): The request data containing HTTP payload information.
        """
        print("\nHTTP Payload:")
        if request['http'].payload:
            self.handle_payload_display(request['http'])
        else:
            print("  No payload")

    def handle_payload_display(self, http):
        """Handle the display of HTTP payload data, including compressed content.

        Args:
            http: The HTTP object containing payload data.
        """
        try:
            if isinstance(http.payload, bytes):
                if 'content-encoding' in http.headers and http.headers['content-encoding'] == 'gzip':
                    self.display_gzipped_payload(http.payload)
                else:
                    print(f"  {http.payload.decode('utf-8', errors='ignore')}")
            else:
                print(f"  {http.payload}")
        except Exception:
            print(f"  [Binary data - {len(http.payload)} bytes]")

    def display_gzipped_payload(self, payload):
        """Display gzip-compressed payload data.

        Args:
            payload (bytes): The compressed payload data.
        """
        try:
            gzip_data = BytesIO(payload)
            with gzip.GzipFile(fileobj=gzip_data, mode='rb') as gz:
                decoded_payload = gz.read().decode('utf-8', errors='ignore')
            print(f"  {decoded_payload}")
        except Exception:
            print(f"  [Gzipped content - {len(payload)} bytes]")