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
        "You are a cybersecurity assistant. Given a natural language description, output a single ffuf command string. "
        "Do not explain or add formatting like code blocks, only return the full shell command.\n"
        "Fuzz Faster U Fool - v2.1.0-dev\n"
        "\nHTTP OPTIONS:\n"
        "  -H                  Header \"Name: Value\", separated by colon. Multiple -H flags are accepted.\n"
        "  -X                  HTTP method to use\n"
        "  -b                  Cookie data \"NAME1=VALUE1; NAME2=VALUE2\" for copy as curl functionality.\n"
        "  -cc                 Client cert for authentication. Client key needs to be defined as well for this to work\n"
        "  -ck                 Client key for authentication. Client certificate needs to be defined as well for this to work\n"
        "  -d                  POST data\n"
        "  -http2              Use HTTP2 protocol (default: false)\n"
        "  -ignore-body        Do not fetch the response content. (default: false)\n"
        "  -r                  Follow redirects (default: false)\n"
        "  -raw                Do not encode URI (default: false)\n"
        "  -recursion          Scan recursively. Only FUZZ keyword is supported, and URL (-u) has to end in it. (default: false)\n"
        "  -recursion-depth    Maximum recursion depth. (default: 0)\n"
        "  -recursion-strategy Recursion strategy: \"default\" for a redirect based, and \"greedy\" to recurse on all matches (default: default)\n"
        "  -replay-proxy       Replay matched requests using this proxy.\n"
        "  -sni                Target TLS SNI, does not support FUZZ keyword\n"
        "  -timeout            HTTP request timeout in seconds. (default: 10)\n"
        "  -u                  Target URL\n"
        "  -x                  Proxy URL (SOCKS5 or HTTP). For example: http://127.0.0.1:8080 or socks5://127.0.0.1:8080\n"
        "\nGENERAL OPTIONS:\n"
        "  -V                  Show version information. (default: false)\n"
        "  -ac                 Automatically calibrate filtering options (default: false)\n"
        "  -acc                Custom auto-calibration string. Can be used multiple times. Implies -ac\n"
        "  -ach                Per host autocalibration (default: false)\n"
        "  -ack                Autocalibration keyword (default: FUZZ)\n"
        "  -acs                Custom auto-calibration strategies. Can be used multiple times. Implies -ac\n"
        "  -c                  Colorize output. (default: false)\n"
        "  -config             Load configuration from a file\n"
        "  -json               JSON output, printing newline-delimited JSON records (default: false)\n"
        "  -maxtime            Maximum running time in seconds for entire process. (default: 0)\n"
        "  -maxtime-job        Maximum running time in seconds per job. (default: 0)\n"
        "  -noninteractive     Disable the interactive console functionality (default: false)\n"
        "  -p                  Seconds of `delay` between requests, or a range of random delay. For example \"0.1\" or \"0.1-2.0\"\n"
        "  -rate               Rate of requests per second (default: 0)\n"
        "  -s                  Do not print additional information (silent mode) (default: false)\n"
        "  -sa                 Stop on all error cases. Implies -sf and -se. (default: false)\n"
        "  -scraperfile        Custom scraper file path\n"
        "  -scrapers           Active scraper groups (default: all)\n"
        "  -se                 Stop on spurious errors (default: false)\n"
        "  -search             Search for a FFUFHASH payload from ffuf history\n"
        "  -sf                 Stop when > 95% of responses return 403 Forbidden (default: false)\n"
        "  -t                  Number of concurrent threads. (default: 40)\n"
        "  -v                  Verbose output, printing full URL and redirect location (if any) with the results. (default: false)\n"
        "\nMATCHER OPTIONS:\n"
        "  -mc                 Match HTTP status codes, or \"all\" for everything. (default: 200-299,301,302,307,401,403,405,500)\n"
        "  -ml                 Match amount of lines in response\n"
        "  -mmode              Matcher set operator. Either of: and, or (default: or)\n"
        "  -mr                 Match regexp\n"
        "  -ms                 Match HTTP response size\n"
        "  -mt                 Match how many milliseconds to the first response byte, either greater or less than. EG: >100 or <100\n"
        "  -mw                 Match amount of words in response\n"
        "\nFILTER OPTIONS:\n"
        "  -fc                 Filter HTTP status codes from response. Comma separated list of codes and ranges\n"
        "  -fl                 Filter by amount of lines in response. Comma separated list of line counts and ranges\n"
        "  -fmode              Filter set operator. Either of: and, or (default: or)\n"
        "  -fr                 Filter regexp\n"
        "  -fs                 Filter HTTP response size. Comma separated list of sizes and ranges\n"
        "  -ft                 Filter by number of milliseconds to the first response byte, either greater or less than. EG: >100 or <100\n"
        "  -fw                 Filter by amount of words in response. Comma separated list of word counts and ranges\n"
        "\nINPUT OPTIONS:\n"
        "  -D                  DirSearch wordlist compatibility mode. Used in conjunction with -e flag. (default: false)\n"
        "  -e                  Comma separated list of extensions. Extends FUZZ keyword.\n"
        "  -enc                Encoders for keywords, eg. 'FUZZ:urlencode b64encode'\n"
        "  -ic                 Ignore wordlist comments (default: false)\n"
        "  -input-cmd          Command producing the input. --input-num is required when using this input method. Overrides -w.\n"
        "  -input-num          Number of inputs to test. Used in conjunction with --input-cmd. (default: 100)\n"
        "  -input-shell        Shell to be used for running command\n"
        "  -mode               Multi-wordlist operation mode. Available modes: clusterbomb, pitchfork, sniper (default: clusterbomb)\n"
        "  -request            File containing the raw http request\n"
        "  -request-proto      Protocol to use along with raw request (default: https)\n"
        "  -w                  Wordlist file path and (optional) keyword separated by colon. eg. '/path/to/wordlist:KEYWORD'\n"
        "\nOUTPUT OPTIONS:\n"
        "  -debug-log          Write all of the internal logging to the specified file.\n"
        "  -o                  Write output to file\n"
        "  -od                 Directory path to store matched results to.\n"
        "  -of                 Output file format. Available formats: json, ejson, html, md, csv, ecsv (or, 'all' for all formats) (default: json)\n"
        "  -or                 Don't create the output file if we don't have results (default: false)"
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
# 4. python aist.py "Scan http://localhost:3000⁠ for hidden paths using wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt with 50 threads"
