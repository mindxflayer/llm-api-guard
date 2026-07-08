from flask import Flask, request

app = Flask(__name__)

@app.post("/submit")
def submit():
    data = request.json["data"]
    return data
