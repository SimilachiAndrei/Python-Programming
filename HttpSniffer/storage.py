from collections import deque
import threading


class RequestStorage:
    def __init__(self, max_size=100):
        self.requests = deque(maxlen=max_size)
        self.request_lock = threading.Lock()

    def add_request(self, request_data):
        with self.request_lock:
            self.requests.append(request_data)
            return len(self.requests) - 1
