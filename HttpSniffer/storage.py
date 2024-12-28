from collections import deque
import threading


class RequestStorage:
    def __init__(self, max_size=100):
        self.requests = deque(maxlen=max_size)
        self.request_lock = threading.Lock()
