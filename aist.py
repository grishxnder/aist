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

# Get ffuf command directly from LLM
def get_ffuf_command_from_prompt(client, text: str) -> str:
    system_prompt = (
        "You are a cybersecurity assistant. Given a natural language description, output a single ffuf command string."
        " Do not explain or add formatting like code blocks, only return the full shell command."
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
    command = resp.choices[0].message.content.strip()
    return command

# Analyze ffuf output using LLM
def analyze_output_with_llm(client, output: str) -> str:
    analysis_prompt = (
        "You are a security analyst. Analyze the following ffuf scan output and describe any potential security issues you find,"
        " such as open directories, interesting response codes, or signs of vulnerabilities."
    )
    messages = [
        {"role": "system", "content": analysis_prompt},
        {"role": "user", "content": output}
    ]
    resp = client.chat.completions.create(
        extra_headers={
            "HTTP-Referer": "local-testing",
            "X-Title": "ffuf-output-analysis"
        },
        extra_body={},
        model="qwen/qwen3-32b:free",
        messages=messages,
    )
    return resp.choices[0].message.content.strip()

# Run ffuf command and return output
def run_ffuf_command(command: str) -> str:
    print(f"Running: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    output_lines = []
    for line in process.stdout:
        print(line, end='')
        output_lines.append(line)
    process.wait()
    return ''.join(output_lines)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run ffuf using LLM-generated command and analyze output.')
    parser.add_argument('description', help='Natural language description of the fuzzing task')
    args = parser.parse_args()

    client = load_api_client()
    ffuf_command = get_ffuf_command_from_prompt(client, args.description)
    ffuf_output = run_ffuf_command(ffuf_command)
    analysis = analyze_output_with_llm(client, ffuf_output)

    print("\n--- LLM Analysis of ffuf Output ---")
    print(analysis)

# Usage:
# 1. pip install openai
# 2. sudo apt install ffuf
# 3. export OPENROUTER_API_KEY="<your_api_key>"
# 4. python ffuf_llm_wrapper.py "Scan https://example.com for hidden paths using wordlist /usr/share/wordlists/dirb/common.txt with 50 threads"
