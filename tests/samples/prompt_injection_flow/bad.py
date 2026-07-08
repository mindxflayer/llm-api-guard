from flask import Flask, request

app = Flask(__name__)

@app.post("/chat")
def chat_handler():
    user_input = request.json["text"]
    prompt = f"User message: {user_input}. Respond to this."
    result = llm_generate(prompt)
    return result

def llm_generate(prompt_str):
    return prompt_str
