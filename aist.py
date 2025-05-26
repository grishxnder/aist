import os
import subprocess
import json
import argparse
from openai import OpenAI

# Load OpenRouter API client for Qwen3-32B (free)
def load_api_client():
    api_key = os.getenv('OPENROUTER_API_KEY')
    if not api_key:
        raise EnvironmentError('Please set the OPENROUTER_API_KEY environment variable')
    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )
    return client

# Use LLM to parse natural-language prompt into JSON parameters for ffuf
def parse_user_text_to_params(client, text: str) -> dict:
    system_prompt = (
        "You are a CLI assistant. Given a user request, output a JSON with keys:"
        " target (URL or host), wordlist (path), threads (int), extra_args (string of other ffuf args)."
        " Only output valid JSON without additional text or code blocks."
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": text}
    ]
    resp = client.chat.completions.create(
        extra_headers={
            "HTTP-Referer": "local-testing",
            "X-Title": "ffuf-llm-wrapper"
        },
        extra_body={},
        model="qwen/qwen3-32b:free",
        messages=messages,
    )
    raw = resp.choices[0].message.content.strip()
    try:
        params = json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError(f"Failed to parse JSON: {raw}")
    # Validate keys
    if 'target' not in params or 'wordlist' not in params:
        raise KeyError(f"Missing required fields in JSON: {params}")
    return params

# Build and run ffuf command
def run_ffuf(params: dict):
    cmd = [
        "ffuf",
        "-u", f"{params['target']}/FUZZ",
        "-w", params['wordlist'],
        "-t", str(params.get('threads', 40)),
    ]
    if params.get('extra_args'):
        cmd += params['extra_args'].split()
    print(f"Running: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in proc.stdout:
        print(line, end='')
    proc.wait()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run ffuf from natural language using Qwen3-32B.')
    parser.add_argument('description', help='Natural language description for the fuzzing task')
    args = parser.parse_args()

    client = load_api_client()
    params = parse_user_text_to_params(client, args.description)
    run_ffuf(params)

# Usage:
# 1. pip install openai ffuf
# 2. export OPENROUTER_API_KEY="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"\# 3. Ensure ffuf is installed
# 4. python ffuf_llm_wrapper.py "Scan https://example.com for directories using wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt with 50 threads"
