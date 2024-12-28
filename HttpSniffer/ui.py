from io import BytesIO
import gzip
import sys


class UI:
    def __init__(self, request_store):
        self.request_store = request_store

    def _display_menu(self):
        print("\nCommands:")
        print("1. List all captured requests")
        print("2. View request details")
        print("3. Exit program")


    def _list_requests(self):
        requests = self.request_store.list_requests()
        print("\nCaptured Requests:")
        for idx, req in requests:
            if req['http'].is_response:
                print(f"{idx}. Response: {req['http'].status_code} from {req['ip'].src_address}")
            else:
                print(f"{idx}. {req['http'].method} to {req['ip'].dst_address}")
