import asyncio
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple
from openai import AsyncOpenAI

try:
    from dotenv import load_dotenv
    load_dotenv(Path(sys.prefix) / ".env")
    load_dotenv()
except ImportError:
    pass

TINY_PNG = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

PROVIDERS: Dict[str, Tuple[str, str]] = {
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY"),
    "mistral": ("https://api.mistral.ai/v1", "MISTRAL_API_KEY"),
    "nvidia": ("https://integrate.api.nvidia.com/v1", "NVIDIA_API_KEY"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/", "GEMINI_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
}

# Synced 1:1 with DEFAULT_TEXT_CHAIN and DEFAULT_VISION_CHAIN in llm_harness.py
CANDIDATES: List[Tuple[str, str, bool]] = [
    # 1. Groq Text (150ms - 1.1s)
    ("groq", "openai/gpt-oss-120b", False),
    ("groq", "openai/gpt-oss-20b", False),
    ("groq", "qwen/qwen3.8-27b", False),
    # 2. NVIDIA Direct Text & Vision (1s - 10s, 40 RPM)
    ("nvidia", "nvidia/nemotron-3-super-120b-a12b", False),
    ("nvidia", "nvidia/nemotron-3-ultra-550b-a55b", False),
    ("nvidia", "openai/gpt-oss-20b", False),
    ("nvidia", "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning", True),
    ("nvidia", "nvidia/nemotron-3.5-super-vl-120b-a12b", True),
    # 3. OpenRouter Free Text & Vision
    ("openrouter", "nvidia/nemotron-3-ultra-550b-a55b:free", False),
    ("openrouter", "nvidia/nemotron-3-super-120b-a12b:free", False),
    ("openrouter", "minimax/minimax-m3.1-flash:free", False),
    ("openrouter", "dots-studio/dots-3-note-preview:free", True),
    ("openrouter", "openrouter/free", False),
    # 4. Mistral & Gemini Fallbacks
    ("mistral", "ministral-14b-latest", False),
    ("gemini", "gemini-3.5-flash", True),
]


async def probe(prov: str, model: str, vision: bool) -> bool:
    base_url, env_key = PROVIDERS[prov]
    key = os.environ.get(env_key, "").strip().strip("'\"")
    if not key:
        print(f"  [SKIP] {prov:<10} | {model:<46} | Missing ${env_key}")
        return False

    if prov == "mistral":
        await asyncio.sleep(1.5)

    content = (
        [{"type": "text", "text": "Return JSON status ok"}, {"type": "image_url", "image_url": {"url": TINY_PNG}}]
        if vision
        else "Return JSON status ok"
    )
    t0 = time.perf_counter()
    async with AsyncOpenAI(base_url=base_url, api_key=key, max_retries=0, timeout=20.0) as client:
        try:
            resp = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": 'Respond ONLY with valid JSON: {"status": "ok"}'},
                    {"role": "user", "content": content},
                ],
                max_tokens=512,
                temperature=0.0,
            )
            ms = (time.perf_counter() - t0) * 1000.0
            raw = (resp.choices[0].message.content or "").strip().replace("\n", " ")[:35]
            if not raw:
                print(f"  [WARN] {prov:<10} | {model:<46} | {'VISION' if vision else 'TEXT  '} | {ms:>5.0f} ms | Empty content")
                return False
            print(f"  [PASS] {prov:<10} | {model:<46} | {'VISION' if vision else 'TEXT  '} | {ms:>5.0f} ms | {raw}")
            return True
        except Exception as e:
            ms = (time.perf_counter() - t0) * 1000.0
            cause = getattr(e, "__cause__", None) or e
            first = (str(cause).splitlines() or [""])[0][:50] or repr(cause)[:50]
            status = getattr(e, "status_code", "-")
            print(
                f"  [FAIL] {prov:<10} | {model:<46} | {'VISION' if vision else 'TEXT  '} | "
                f"{ms:>5.0f} ms | {status} {type(e).__name__}: {first}"
            )
            return False


async def main() -> None:
    print(f"Loaded .env from: {Path(sys.prefix) / '.env'}")
    passed = 0
    for p, m, v in CANDIDATES:
        if await probe(p, m, v):
            passed += 1
    print(f"\n[SUMMARY] {passed}/{len(CANDIDATES)} routes healthy and ready.")


if __name__ == "__main__":
    asyncio.run(main())