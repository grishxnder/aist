import os
import subprocess
import json
import argparse
import sqlite3
import pickle
import faiss
import numpy as np
from openai import OpenAI

# === Configuration for RAG ===
DB_PATH = 'examples.db'
FAISS_INDEX_PATH = 'examples.index'
EMBEDDING_MODEL = 'openai-embedding-3-small'
TOP_K = 3

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


# Compute embedding for a text via OpenRouter/OpenAI
def get_embedding(client, text: str) -> list:
    resp = client.embeddings.create(model=EMBEDDING_MODEL, input=text)
    return resp.data[0].embedding


# Initialize or load FAISS index and example metadata
def load_rag_resources():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # ensure table exists
    cur.execute(
        'CREATE TABLE IF NOT EXISTS examples (id INTEGER PRIMARY KEY, description TEXT, command TEXT, embedding BLOB)'
    )
    rows = cur.execute('SELECT id, embedding FROM examples').fetchall()
    if not rows:
        raise RuntimeError('No examples in database for RAG retrieval')
    ids, embeddings = zip(*rows)
    embeddings = np.array([pickle.loads(e) for e in embeddings], dtype='float32')
    d = embeddings.shape[1]
    index = faiss.IndexFlatL2(d)
    index.add(embeddings)
    return conn, index, list(ids)


# Retrieve top-k similar examples from the RAG store
def retrieve_similar_examples(client, index, ids, description: str, k=TOP_K):
    q_emb = np.array([get_embedding(client, description)], dtype='float32')
    D, I = index.search(q_emb, k)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    examples = []
    for idx in I[0]:
        row = cur.execute('SELECT description, command FROM examples WHERE id=?', (ids[idx],)).fetchone()
        examples.append({'desc': row[0], 'cmd': row[1]})
    conn.close()
    return examples

# Generate ffuf command using LLM with RAG context
def generate_ffuf_command(client, description: str, index, ids, previous_error: str = "") -> str:
    # Load system prompt
    system_prompt = open('recon_run.txt').read()
    # Retrieve examples via RAG
    examples = retrieve_similar_examples(client, index, ids, description)
    rag_context = "".join(
        f"Example Description: {ex['desc']}\nExample Command: {ex['cmd']}\n---\n" for ex in examples
    )
    # Build user prompt
    user_prompt = f"{rag_context}\nTask: {description}"
    if previous_error:
        user_prompt += f"\nPrevious error: {previous_error}"

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_prompt}
    ]
    resp = client.chat.completions.create(
        extra_headers={"HTTP-Referer": "local-testing", "X-Title": "ffuf-llm-wrapper"},
        extra_body={},
        model="deepseek/deepseek-r1-distill-llama-70b:free",
        messages=messages,
    )
    return resp.choices[0].message.content.strip()

 
# Run ffuf command and return output, error output, and return code
def run_ffuf_command(command: str, timeout: int = 30):
    print(f"Running: {command}")
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        stderr += "\nCommand timed out after {} seconds.".format(timeout)
        return stdout, stderr, 1
    except Exception as e:
        return "", str(e), 1

    if process.returncode != 0:
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
        model="deepseek/deepseek-r1-distill-llama-70b:free",
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
