#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"

if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
pip install --upgrade pip >/dev/null
pip install -r "$ROOT_DIR/requirements.txt" >/dev/null

export OPENAI_CHAT_MODEL="${OPENAI_CHAT_MODEL:-gpt-4.1-mini}"
export OPENAI_EMBED_MODEL="${OPENAI_EMBED_MODEL:-text-embedding-3-small}"
export OPENAI_API_KEY="${OPENAI_API_KEY:-}"
export LOCAL_ANALYSIS_TIMEOUT="${LOCAL_ANALYSIS_TIMEOUT:-240}"
export LOCAL_ANALYSIS_MAX_TOKENS="${LOCAL_ANALYSIS_MAX_TOKENS:-900}"
export LOCAL_ANALYSIS_MAX_ARTIFACTS="${LOCAL_ANALYSIS_MAX_ARTIFACTS:-60}"
export LOCAL_ANALYSIS_NUM_CTX="${LOCAL_ANALYSIS_NUM_CTX:-4096}"

echo "[config] OPENAI_CHAT_MODEL=$OPENAI_CHAT_MODEL"
echo "[config] OPENAI_EMBED_MODEL=$OPENAI_EMBED_MODEL"
echo "[config] LOCAL_ANALYSIS_TIMEOUT=$LOCAL_ANALYSIS_TIMEOUT"
echo "[config] LOCAL_ANALYSIS_MAX_TOKENS=$LOCAL_ANALYSIS_MAX_TOKENS"
echo "[config] LOCAL_ANALYSIS_MAX_ARTIFACTS=$LOCAL_ANALYSIS_MAX_ARTIFACTS"
echo "[config] LOCAL_ANALYSIS_NUM_CTX=$LOCAL_ANALYSIS_NUM_CTX"
if [[ -z "$OPENAI_API_KEY" ]]; then
  echo "[warn] OPENAI_API_KEY is empty. OpenAI analysis button will be disabled."
else
  echo "[config] OPENAI_API_KEY is set."
fi

python -m webapp.app.main --host 127.0.0.1 --port 17888 --open
