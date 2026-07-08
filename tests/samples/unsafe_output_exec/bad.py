class OpenAICompletion:
    def __init__(self):
        self.choices = [Choice()]

class Choice:
    def __init__(self):
        self.message = Message()

class Message:
    def __init__(self):
        self.content = "print('hello')"

response = OpenAICompletion()
code_to_run = response.choices[0].message.content
eval(code_to_run)
