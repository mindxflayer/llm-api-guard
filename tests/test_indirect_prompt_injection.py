import os
import shutil
import tempfile
import pytest
from scanner.core import Runner
from scanner.static.indirect_prompt_injection import IndirectPromptInjection
from scanner.static.prompt_injection_flow import PromptInjectionFlow

def test_indirect_prompt_injection_web_fetch():
    temp_dir = tempfile.mkdtemp()
    try:
        code = (
            "import requests\n"
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            "@app.route('/scan')\n"
            "def scan():\n"
            "    url = request.args.get('url')\n"
            "    data = requests.get(url).text\n"
            "    prompt = f'Summarize: {data}'\n"
            "    llm_predict(prompt)\n"
        )
        with open(os.path.join(temp_dir, "app.py"), "w", encoding="utf-8") as f:
            f.write(code)
            
        plugin_indirect = IndirectPromptInjection()
        plugin_direct = PromptInjectionFlow()
        
        runner_indirect = Runner([plugin_indirect], config={"checks": {"indirect_prompt_injection": True}, "live_checks": {}})
        findings_indirect = runner_indirect.run(temp_dir)
        
        runner_direct = Runner([plugin_direct], config={"checks": {"prompt_injection_flow": True}, "live_checks": {}})
        findings_direct = runner_direct.run(temp_dir)
        
        assert len(findings_indirect) == 1
        assert findings_indirect[0].rule == "indirect_prompt_injection"
        
        assert len(findings_direct) == 1
        assert findings_direct[0].rule == "prompt_injection_flow"
    finally:
        shutil.rmtree(temp_dir)

def test_indirect_prompt_injection_rag_search():
    temp_dir = tempfile.mkdtemp()
    try:
        code = (
            "def rag_flow(db):\n"
            "    docs = db.similarity_search('query')\n"
            "    prompt = f'System: {docs}'\n"
            "    generate_response(prompt)\n"
        )
        with open(os.path.join(temp_dir, "rag.py"), "w", encoding="utf-8") as f:
            f.write(code)
            
        plugin = IndirectPromptInjection()
        runner = Runner([plugin], config={"checks": {"indirect_prompt_injection": True}, "live_checks": {}})
        findings = runner.run(temp_dir)
        
        assert len(findings) == 1
        assert findings[0].rule == "indirect_prompt_injection"
    finally:
        shutil.rmtree(temp_dir)

def test_indirect_prompt_injection_file_read():
    temp_dir = tempfile.mkdtemp()
    try:
        code = (
            "def file_flow():\n"
            "    with open('info.txt') as f:\n"
            "        content = f.read()\n"
            "    prompt = 'Explain this: ' + content\n"
            "    model_generate(prompt)\n"
        )
        with open(os.path.join(temp_dir, "reader.py"), "w", encoding="utf-8") as f:
            f.write(code)
            
        plugin = IndirectPromptInjection()
        runner = Runner([plugin], config={"checks": {"indirect_prompt_injection": True}, "live_checks": {}})
        findings = runner.run(temp_dir)
        
        assert len(findings) == 1
        assert findings[0].rule == "indirect_prompt_injection"
    finally:
        shutil.rmtree(temp_dir)

def test_indirect_prompt_injection_negative_request_only():
    temp_dir = tempfile.mkdtemp()
    try:
        code = (
            "from flask import request\n"
            "def handler():\n"
            "    val = request.args.get('q')\n"
            "    prompt = 'Hello ' + val\n"
            "    predict_llm(prompt)\n"
        )
        with open(os.path.join(temp_dir, "handler.py"), "w", encoding="utf-8") as f:
            f.write(code)
            
        plugin = IndirectPromptInjection()
        runner = Runner([plugin], config={"checks": {"indirect_prompt_injection": True}, "live_checks": {}})
        findings = runner.run(temp_dir)
        
        assert len(findings) == 0
    finally:
        shutil.rmtree(temp_dir)
