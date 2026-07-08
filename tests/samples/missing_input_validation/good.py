from flask import Flask, request
from pydantic import BaseModel

class Schema(BaseModel):
    data: str

app = Flask(__name__)

@app.post("/submit")
def submit():
    payload = Schema.model_validate(request.json)
    return payload.data
