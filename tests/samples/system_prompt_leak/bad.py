from flask import Flask, request, jsonify

app = Flask(__name__)

@app.post("/chat")
def chat():
    system_prompt = "You are a secret agent."
    user_input = request.json["text"]
    response_msg = "Hello!"
    return jsonify({
        "response": response_msg,
        "system_prompt": system_prompt
    })
