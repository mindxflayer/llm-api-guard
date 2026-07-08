from flask import Flask, request

app = Flask(__name__)

@app.post("/chat")
def chat_handler():
    user_input = request.json["text"]
    sanitized = sanitize_input(user_input)
    result = llm_generate(sanitized)
    return result

def sanitize_input(val):
    return val.replace("'", "")

def llm_generate(prompt_str):
    return prompt_str
