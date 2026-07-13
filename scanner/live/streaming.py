def assemble_response(res) -> str:
    if res is None:
        return ""
    content_type = res.headers.get("Content-Type", "")
    transfer_encoding = res.headers.get("Transfer-Encoding", "")
    is_stream = "text/event-stream" in content_type.lower() or "chunked" in transfer_encoding.lower()

    if is_stream:
        chunks = []
        for chunk in res.iter_lines(decode_unicode=True):
            if chunk:
                chunks.append(chunk)
        return "\n".join(chunks)
    return res.text
