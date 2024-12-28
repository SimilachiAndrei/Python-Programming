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
