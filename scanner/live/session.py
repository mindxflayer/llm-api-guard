import uuid
import logging
from scanner.live.streaming import assemble_response

logger = logging.getLogger("llm-api-guard")

class LiveSession:
    def __init__(self, requester, url: str, headers: dict = None, session_field_name: str = "conversation_id", session_id_mode: str = "client"):
        self.requester = requester
        self.url = url
        self.headers = headers or {}
        self.session_field_name = session_field_name
        self.session_id_mode = session_id_mode
        self.session_id = None

        if self.session_id_mode == "client":
            self.session_id = str(uuid.uuid4())

        self.transcript = []

    def send_turn(self, prompt: str) -> str:
        req_headers = dict(self.headers)
        json_body = {"prompt": prompt}
        if self.session_id:
            json_body[self.session_field_name] = self.session_id

        try:
            res = self.requester.post(self.url, headers=req_headers, json=json_body, stream=True)
        except Exception as e:
            logger.warning(f"LiveSession request failed: {e}")
            res = None

        if res is None:
            return ""

        if self.session_id_mode == "server" and not self.session_id:
            try:
                data = res.json()
                if isinstance(data, dict) and self.session_field_name in data:
                    self.session_id = str(data[self.session_field_name])
            except Exception:
                pass
            if not self.session_id:
                header_val = res.headers.get(self.session_field_name)
                if header_val:
                    self.session_id = str(header_val)

        response_text = assemble_response(res)
        turn_number = len(self.transcript) + 1
        self.transcript.append({
            "turn": turn_number,
            "prompt": prompt,
            "response": response_text
        })

        return response_text
