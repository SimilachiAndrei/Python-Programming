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


    def display_detail_options(self):
        print("\nChoose what information to view (comma-separated):")
        print("1. Ethernet")
        print("2. IP")
        print("3. TCP")
        print("4. HTTP Headers")
        print("5. HTTP Payload")
        print("6. All")

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
