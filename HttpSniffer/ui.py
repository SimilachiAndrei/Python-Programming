from io import BytesIO
import gzip
import sys

class UI:
    def __init__(self, request_store):
        self.request_store = request_store

    def display_menu(self):
        print("\nCommands:")
        print("1. List all captured requests")
        print("2. View request details")
        print("3. Exit program")

    def list_requests(self):
        requests = self.request_store.list_requests()
        print("\nCaptured Requests:")
        for idx, req in requests:
            if req['http'].is_response:
                print(f"{idx}. Response: {req['http'].status_code} from {req['ip'].src_address}")
            else:
                print(f"{idx}. {req['http'].method} to {req['ip'].dst_address}")

    def view_request_details(self):
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
        print("\nChoose what information to view (comma-separated):")
        print("1. Ethernet")
        print("2. IP")
        print("3. TCP")
        print("4. HTTP Headers")
        print("5. HTTP Payload")
        print("6. All")

    def display_selected_details(self, request, choices):
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
        print("\nEthernet Layer:")
        print(f"  Source MAC: {request['ethernet'].src_mac}")
        print(f"  Destination MAC: {request['ethernet'].dst_mac}")

    def display_ip_info(self, request):
        print("\nIP Layer:")
        print(f"  Source IP: {request['ip'].src_address}")
        print(f"  Destination IP: {request['ip'].dst_address}")
        print(f"  Protocol: {request['ip'].protocol}")

    def display_tcp_info(self, request):
        print("\nTCP Layer:")
        print(f"  Source Port: {request['tcp'].sport}")
        print(f"  Destination Port: {request['tcp'].dport}")

    def display_http_headers(self, request):
        print("\nHTTP Headers:")
        if request['http'].is_response:
            print(f"  Status: {request['http'].version} {request['http'].status_code} {request['http'].status_message}")
        else:
            print(f"  Request: {request['http'].method} {request['http'].uri} {request['http'].version}")

        for key, value in request['http'].headers.items():
            print(f"  {key}: {value}")

    def display_http_payload(self, request):
        print("\nHTTP Payload:")
        if request['http'].payload:
            self.handle_payload_display(request['http'])
        else:
            print("  No payload")

    def handle_payload_display(self, http):
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
        try:
            gzip_data = BytesIO(payload)
            with gzip.GzipFile(fileobj=gzip_data, mode='rb') as gz:
                decoded_payload = gz.read().decode('utf-8', errors='ignore')
            print(f"  {decoded_payload}")
        except Exception:
            print(f"  [Gzipped content - {len(payload)} bytes]")