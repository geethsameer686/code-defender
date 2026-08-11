"""
Standalone Prod LLM Gateway test script
=======================================

Minimal script for hitting the Walmart PROD LLM Gateway with the only two
models used by this repo:

    * gemini-2.5-flash-lite@001   — chat (via google-genai)
    * text-embedding-3-large      — embeddings, 3072-dim (via openai SDK)

Usage
-----
    # Provide the API key (any one of these works):
    export LLM_GATEWAY_API_KEY=<your-key>
    # or drop the key into a file:
    #   ./llmgateway_api_key.txt
    #   /etc/secrets/llmgateway_api_key(.txt)

    # Chat (default):
    python docs/test_prod_llm_gateway.py "What is 2 + 2?"

    # Embedding:
    python docs/test_prod_llm_gateway.py --mode embed "hello world"

Requires: google-genai, openai, httpx
"""

from __future__ import annotations

import argparse
import os
import ssl
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Config — matches llm_gateway.py + docs/generate_audience_summary.py
# ---------------------------------------------------------------------------
PROD_ENDPOINT = "https://wmtllmgateway.prod.walmart.com/wmtllmgateway"

CHAT_MODEL      = "gemini-2.5-flash-lite@001"
EMBED_MODEL     = "text-embedding-3-large"
EMBED_API_VER   = "2024-10-21"
DEFAULT_USER_NAME = "g0v021t"  # matches llm_gateway.py _LLM_GW_USER_NAME



api_key = "eyJzZ252ZXIiOiIxIiwiYWxnIjoiSFMyNTYiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiIzMjEiLCJzdWIiOiI0MzgiLCJpc3MiOiJXTVRMTE1HQVRFV0FZLVBST0QiLCJhY3QiOiJnMHYwMjF0IiwidHlwZSI6IkFQUCIsImlhdCI6MTc3MTUzNDcxOSwiZXhwIjoxNzg3MDg2NzE5fQ.BD-D12T68cVw3A4-vhYgZo3O5c4Ndqve2Nu4XutIn8Q"
# Candidate locations for the Walmart CA bundle


WMT_CA_PATH = "/Users/g0v021t/Documents/audience_summary_standalone/ca-bundle.crt"



def _load_api_key() -> str:
    # Prefer the hardcoded key at the top of this file
    if api_key and api_key.strip():
        return api_key.strip()
    key = os.environ.get("LLM_GATEWAY_API_KEY")
    if key:
        return key.strip()
    sys.exit(
        "ERROR: No API key found. Hardcode `api_key` at the top of this file "
        "or set the LLM_GATEWAY_API_KEY env var."
    )


def _resolve_ca_path() -> str | None:
    for candidate in (os.environ.get("WMT_CA_PATH"), WMT_CA_PATH):
        if candidate and Path(candidate).exists():
            return candidate
    return None


def _gateway_headers(api_key: str, user_name: str) -> dict:
    return {
        "X-Api-Key": api_key,
        "WM_LLM_GW.USER_TYPE": "ASSOCIATE",
        "WM_LLM_GW.USER_NAME": user_name,
    }


# ---------------------------------------------------------------------------
# Chat — Gemini via google-genai
# ---------------------------------------------------------------------------
def call_gemini(
    user_input: str,
    system_prompt: str = "You are a helpful assistant. Answer concisely.",
    model: str = CHAT_MODEL,
    temperature: float = 0.3,
    user_name: str = DEFAULT_USER_NAME,
) -> str:
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        sys.exit("ERROR: google-genai not installed. Run: pip install google-genai")

    api_key = _load_api_key()
    ca_path = _resolve_ca_path()

    # Gateway proxies Gemini — force SDK off direct Vertex path.
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"

    # Walmart LLM Gateway sits behind a self-signed / private CA chain — must
    # be trusted before google-genai builds its internal httpx client.
    if ca_path:
        os.environ["SSL_CERT_FILE"]      = ca_path
        os.environ["REQUESTS_CA_BUNDLE"] = ca_path
        print(f"[INFO] Using CA bundle: {ca_path}")
    else:
        print("[WARN] No Walmart CA bundle found — using system trust store.")

    headers = _gateway_headers(api_key, user_name)
    print(f"[INFO] Endpoint : {PROD_ENDPOINT}")
    print(f"[INFO] Model    : {model}")
    print(f"[INFO] Headers  : X-Api-Key=***, WM_LLM_GW.USER_TYPE=ASSOCIATE, "
          f"WM_LLM_GW.USER_NAME={user_name}")

    client = genai.Client(
        api_key=api_key,
        http_options={"base_url": PROD_ENDPOINT, "headers": headers},
    )
    config = types.GenerateContentConfig(
        system_instruction=system_prompt,
        temperature=temperature,
    )
    response = client.models.generate_content(
        model=model,
        contents=user_input,
        config=config,
    )
    return (response.text or "").strip()


# ---------------------------------------------------------------------------
# Embedding — text-embedding-3-large via openai SDK
# ---------------------------------------------------------------------------
def call_embedding(
    text: str,
    model: str = EMBED_MODEL,
    api_version: str = EMBED_API_VER,
    user_name: str = DEFAULT_USER_NAME,
) -> list[float]:
    try:
        import httpx
        import openai
    except ImportError:
        sys.exit("ERROR: openai/httpx not installed. Run: pip install openai httpx")

    api_key = _load_api_key()
    ca_path = _resolve_ca_path()

    if ca_path:
        os.environ["SSL_CERT_FILE"] = ca_path
        os.environ["REQUESTS_CA_BUNDLE"] = ca_path
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(ca_path)
        http_client = httpx.Client(verify=ctx, headers=_gateway_headers(api_key, user_name))
        print(f"[INFO] Using CA bundle: {ca_path}")
    else:
        http_client = httpx.Client(headers=_gateway_headers(api_key, user_name))
        print("[WARN] No Walmart CA bundle found — using system trust store.")

    print(f"[INFO] Endpoint : {PROD_ENDPOINT}")
    print(f"[INFO] Model    : {model} (api-version={api_version})")
    print(f"[INFO] Headers  : X-Api-Key=***, WM_LLM_GW.USER_TYPE=ASSOCIATE, "
          f"WM_LLM_GW.USER_NAME={user_name}")

    client = openai.OpenAI(
        api_key=api_key,
        base_url=PROD_ENDPOINT,
        http_client=http_client,
    )
    response = client.embeddings.create(
        model=model,
        input=text,
        extra_query={"api-version": api_version},
    )
    return response.data[0].embedding


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
DEFAULT_CHAT_PROMPTS = [
    "What is the capital of Japan? Answer in one sentence.",
    "Give me a fun fact about octopuses in under 30 words.",
    "In 2 sentences, explain what retrieval-augmented generation (RAG) is.",
    "Write a haiku about a Walmart shopping cart.",
    "What is 17 * 23? Reply with just the number.",
]

DEFAULT_EMBED_TEXT = "Walmart LLM Gateway prod — text-embedding-3-large smoke test."


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ping the PROD Walmart LLM Gateway.")
    parser.add_argument(
        "prompt",
        nargs="?",
        default=None,
        help="Optional single prompt (chat) or text (embed). If omitted, runs the default suite.",
    )
    parser.add_argument(
        "--mode",
        choices=["chat", "embed", "both"],
        default="both",
        help="chat = Gemini 2.5 Flash Lite | embed = text-embedding-3-large | both (default)",
    )
    parser.add_argument("--system", default="You are a helpful assistant. Answer concisely.")
    parser.add_argument("--temperature", type=float, default=0.3)
    parser.add_argument("--user-name", default=DEFAULT_USER_NAME)
    return parser.parse_args()


def _run_chat_suite(prompts: list[str], system: str, temperature: float, user_name: str) -> bool:
    print("\n" + "=" * 78)
    print(f"[TEST] Chat — {CHAT_MODEL}")
    print("=" * 78)
    ok = True
    for i, prompt in enumerate(prompts, start=1):
        print(f"\n[chat {i}/{len(prompts)}] prompt: {prompt!r}")
        try:
            reply = call_gemini(
                user_input=prompt,
                system_prompt=system,
                temperature=temperature,
                user_name=user_name,
            )
        except Exception as exc:
            print(f"[chat {i}] FAILED: {exc!r}")
            ok = False
            continue
        print("-" * 78)
        print(reply)
        print("-" * 78)
    return ok


def _run_embed(text: str, user_name: str) -> bool:
    print("\n" + "=" * 78)
    print(f"[TEST] Embedding — {EMBED_MODEL}")
    print("=" * 78)
    print(f"[embed] input: {text!r}")
    try:
        vector = call_embedding(text=text, user_name=user_name)
    except Exception as exc:
        print(f"[embed] FAILED: {exc!r}")
        return False
    print(f"[embed] dim         : {len(vector)}")
    print(f"[embed] first 8 vals: {vector[:8]}")
    print(f"[embed] last 4 vals : {vector[-4:]}")
    return True


def main() -> None:
    args = _parse_args()
    print(f"[INFO] Mode     : {args.mode}")

    chat_prompts = [args.prompt] if args.prompt else DEFAULT_CHAT_PROMPTS
    embed_text   = args.prompt if args.prompt else DEFAULT_EMBED_TEXT

    results: dict[str, bool] = {}

    if args.mode in ("chat", "both"):
        results["chat"] = _run_chat_suite(
            prompts=chat_prompts,
            system=args.system,
            temperature=args.temperature,
            user_name=args.user_name,
        )

    if args.mode in ("embed", "both"):
        results["embed"] = _run_embed(text=embed_text, user_name=args.user_name)

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    for name, ok in results.items():
        print(f"  {name:<6} : {'PASS' if ok else 'FAIL'}")

    sys.exit(0 if all(results.values()) else 1)


if __name__ == "__main__":
    main()
