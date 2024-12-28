# ui.py
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

