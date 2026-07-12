import os
import time
import logging
import requests

class ThrottledRequester:
    def __init__(self, max_requests=50, min_delay=0.5, request_timeout=10, run_timeout=60):
        if max_requests > 200:
            logging.warning("max_requests %d exceeds cap of 200; clamping to 200", max_requests)
            self.max_requests = 200
        else:
            self.max_requests = max_requests
        self.min_delay = min_delay
        self.request_timeout = request_timeout
        self.run_timeout = run_timeout
        self.start_time = time.time()
        self.last_request_time = 0.0
        self.requests_made = 0
        self.requests_succeeded = 0
        self.requests_failed = 0

    @property
    def time_elapsed(self):
        return time.time() - self.start_time

    def _should_block(self):
        if self.time_elapsed >= self.run_timeout:
            return True
        if self.requests_made >= self.max_requests:
            return True
        return False

    def _apply_delay(self):
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < self.min_delay:
            time.sleep(self.min_delay - elapsed)
            now = time.time()
        self.last_request_time = now


    def _execute_request(self, method, url, **kwargs):
        if self._should_block():
            return None

        self.requests_made += 1
        kwargs.setdefault("timeout", self.request_timeout)

        for retry in range(4):
            if self.time_elapsed >= self.run_timeout:
                self.requests_failed += 1
                return None

            if retry > 0:
                backoff = self.min_delay * (2 ** (retry - 1))
                time.sleep(backoff)

            self._apply_delay()

            try:
                response = requests.request(method, url, **kwargs)
                if response.status_code >= 500:
                    continue
                self.requests_succeeded += 1
                return response
            except (requests.exceptions.RequestException, requests.exceptions.Timeout):
                continue

        self.requests_failed += 1
        return None

    def get(self, url, headers=None, **kwargs):
        return self._execute_request("GET", url, headers=headers, **kwargs)

    def post(self, url, headers=None, data=None, json=None, **kwargs):
        return self._execute_request("POST", url, headers=headers, data=data, json=json, **kwargs)

    def get_stats(self) -> dict:
        return {
            "requests_made": self.requests_made,
            "requests_succeeded": self.requests_succeeded,
            "requests_failed": self.requests_failed,
            "time_elapsed": self.time_elapsed
        }
