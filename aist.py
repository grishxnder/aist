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

# Generate ffuf command using LLM
def generate_ffuf_command(client, description: str, previous_error: str = "") -> str:
    print("Generating started")
    system_prompt = ""
    with open('recon_run.txt', 'r') as file:
        system_prompt += file.read()

    user_prompt = description
    if previous_error:
        user_prompt += f"\n\nNote: The previous command failed with the following error:\n \nPlease correct it."

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
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
    return resp.choices[0].message.content.strip()

 
# Run ffuf command and return output, error output, and return code
def run_ffuf_command(command: str):
    print(f"Running: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    if stderr:
        return stdout, stderr, process.returncode
    
    for line in stdout.splitlines():
        print(line)
    return stdout, stderr, process.returncode


# Analyze ffuf output using LLM
def analyze_output_with_llm(client, output: str) -> str:
    print("Analysis started")
    analysis_prompt = ""
    with open('recon_analysis.txt', 'r') as file:
        analysis_prompt += file.read()
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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run ffuf using LLM-generated command and analyze output.')
    parser.add_argument('description', help='Natural language description of the fuzzing task')
    args = parser.parse_args()

    client = load_api_client()

    MAX_WORDS = 5000
    last_error = ""
    ffuf_output = ""
    ffuf_command = ""

    for attempt in range(3):
        ffuf_command = generate_ffuf_command(client, args.description, last_error)
        ffuf_output, ffuf_stderr, returncode = run_ffuf_command(ffuf_command)
        word_count = len(ffuf_output.split())

        if returncode != 0:
            last_error = ffuf_stderr.strip() or "command output returned a non-zero exit code with no additional error message."
            print(f"❌ Command execution failed (code {returncode}):\n{last_error}\n")
            continue
        elif word_count > MAX_WORDS:
            last_error = f"Output too long ({word_count} words). Limit is {MAX_WORDS}."
            print(f"⚠️ Output too verbose. Retrying...\n")
            continue
        else:
            break
    else:
        raise RuntimeError("Failed to generate and execute a valid ffuf command after multiple attempts.")

    analysis = analyze_output_with_llm(client, ffuf_output)

    print("\n--- LLM Analysis of ffuf Output ---")
    print(analysis)

# Usage:
# 1. pip install openai
# 2. sudo apt install ffuf
# 3. export OPENROUTER_API_KEY="<your_api_key>"
# 4. python ffuf_llm_wrapper.py "Scan https://example.com for hidden paths using wordlist /usr/share/wordlists/dirb/common.txt with 50 threads"
