import os

openai_key = os.getenv("OPENAI_API_KEY")
aws_key = os.getenv("AWS_ACCESS_KEY_ID")

class SafeClass:
    def __init__(self):
        self.key = "your_key_here"
