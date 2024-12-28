# ui.py
from io import BytesIO
import gzip
import sys


class UI:
    def __init__(self, request_store):
        self.request_store = request_store

