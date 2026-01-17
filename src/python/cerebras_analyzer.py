#!/usr/bin/env python
import os
import asyncio
import json
import pathlib
import uuid
import shutil
import sys
from typing import AsyncGenerator

import httpx
import git
from pydantic import BaseModel, HttpUrl
from dotenv import load_dotenv

load_dotenv()

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
CEREBRAS_BASE_URL = os.getenv("CEREBRAS_BASE_URL", "https://api.cerebras.net/v1")
CEREBRAS_API_KEY = os.getenv("CEREBRAS_API_KEY")
CEREBRAS_MODEL_ID = os.getenv("CEREBRAS_MODEL_ID", "llama3.1-70b") # Updated to 3.1
CEREBRAS_MAX_TOKENS = int(os.getenv("CEREBRAS_MAX_TOKENS", "4000"))

if not CEREBRAS_API_KEY:
    print(json.dumps({"error": "CEREBRAS_API_KEY not set in environment"}))
    sys.exit(1)

# ----------------------------------------------------------------------
# Helper: shallow clone repo into a temp dir
# ----------------------------------------------------------------------
def shallow_clone(repo_url: str, branch: str) -> pathlib.Path:
    """Clone a repo shallowly (depth=1) and return the absolute path."""
    # Use a local temp dir within the project instead of /tmp for better Windows compatibility if needed
    base_tmp = pathlib.Path(os.getcwd()) / "temp_clones"
    base_tmp.mkdir(exist_ok=True)
    
    tmp_dir = base_tmp / f"cerebra-{uuid.uuid4().hex}"
    tmp_dir.mkdir(parents=True, exist_ok=False)
    
    try:
        git.Repo.clone_from(
            repo_url,
            to_path=str(tmp_dir),
            branch=branch,
            depth=1,
            single_branch=True,
        )
    except Exception as exc:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(f"Git clone failed: {exc}") from exc
    return tmp_dir

# ----------------------------------------------------------------------
# Helper: read all source files
# ----------------------------------------------------------------------
SOURCE_EXTS = {".js", ".ts", ".jsx", ".tsx", ".py", ".java", ".go", ".c", ".cpp"}

def collect_source_files(root: pathlib.Path) -> list[pathlib.Path]:
    files = []
    # Skip common noise dirs
    skip_dirs = {"node_modules", ".git", "dist", "build", "venv", "__pycache__"}
    
    for p in root.rglob("*"):
        if any(skip in p.parts for skip in skip_dirs):
            continue
        if p.is_file() and p.suffix.lower() in SOURCE_EXTS:
            files.append(p)
    return files

# ----------------------------------------------------------------------
# Helper: build the prompt for the LLM
# ----------------------------------------------------------------------
def build_prompt(files: list[pathlib.Path], repo_url: str, branch: str, prefix: str | None) -> str:
    intro = (
        f"You are an expert security auditor and software engineer. Perform a deep audit of the "
        f"following repository:\n"
        f"- URL: {repo_url}\n"
        f"- Branch: {branch}\n"
        f"Identify vulnerabilities, bugs, and performance issues. "
        f"CRITICAL: Return the answer in STRICT JSON format with an 'issues' array.\n"
        f"Schema: {{\"issues\": [{{\"file\":\"path/to/file\",\"line\":42,\"type\":\"security|bug|quality\",\"msg\":\"...\",\"severity\":\"CRITICAL|HIGH|MEDIUM|LOW\"}}]}}\n"
    )
    if prefix:
        intro = prefix + "\n" + intro

    max_chars = 15000 # Increased for better context
    body = ""
    for f in files:
        rel = f.relative_to(f.parent.parent) 
        try:
            content = f.read_text(encoding="utf-8")
        except Exception:
            continue
        snippet = content[:2000] # Take more per file
        part = f"\n--- {rel} ---\n{snippet}\n"
        if len(body) + len(part) > max_chars:
            break
        body += part

    return intro + "\n" + body

# ----------------------------------------------------------------------
# Cerebras Client
# ----------------------------------------------------------------------
async def analyze_repo(repo_url: str, branch: str, prefix: str | None = None):
    repo_path = None
    try:
        # Log start of process
        sys.stderr.write(f"DEBUG: Starting analysis for {repo_url} on branch {branch}\n")
        
        # 1. Clone
        sys.stderr.write("DEBUG: Attempting shallow clone...\n")
        repo_path = shallow_clone(repo_url, branch)
        sys.stderr.write(f"DEBUG: Clone successful. Path: {repo_path}\n")
        
        # 2. Collect
        files = collect_source_files(repo_path)
        sys.stderr.write(f"DEBUG: Collected {len(files)} source files.\n")
        
        # 3. Build Prompt
        prompt = build_prompt(files, repo_url, branch, prefix)
        sys.stderr.write(f"DEBUG: Prompt built. Size: {len(prompt)} chars.\n")

        # 4. API Call
        url = f"{CEREBRAS_BASE_URL}/chat/completions"
        sys.stderr.write(f"DEBUG: Calling Cerebras API at {url}...\n")
        
        headers = {
            "Authorization": f"Bearer {CEREBRAS_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": CEREBRAS_MODEL_ID,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": CEREBRAS_MAX_TOKENS,
            "temperature": 0.2,
            "response_format": {"type": "json_object"} # Force JSON
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            result = response.json()
            
            content = result["choices"][0]["message"]["content"]
            sys.stderr.write("DEBUG: API call successful.\n")
            print(content) # Output result to stdout for parent process

    except Exception as exc:
        error_msg = f"ERROR in Python analyzer: {type(exc).__name__}: {str(exc)}"
        sys.stderr.write(f"{error_msg}\n")
        print(json.dumps({"error": error_msg}))
    finally:
        if repo_path and repo_path.exists():
            sys.stderr.write("DEBUG: Cleaning up temp directory...\n")
            shutil.rmtree(repo_path, ignore_errors=True)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(json.dumps({"error": "Usage: python cerebras_analyzer.py <repo_url> <branch> [prefix]"}))
        sys.exit(1)
    
    repo_url = sys.argv[1]
    branch = sys.argv[2]
    prefix = sys.argv[3] if len(sys.argv) > 3 else None
    
    asyncio.run(analyze_repo(repo_url, branch, prefix))
