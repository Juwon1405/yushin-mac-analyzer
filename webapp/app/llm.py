from __future__ import annotations

import json
import os
import re
from typing import Any

import requests


def build_case_prompt(case_data: dict[str, Any], max_artifacts: int = 60) -> str:
    artifacts = prioritize_artifacts(case_data.get("artifacts", []), limit=max_artifacts)
    summary = case_data.get("summary", {})

    lines = [
        "You are a senior DFIR analyst specialized in macOS incident response.",
        "Analyze parsed forensic artifacts and provide concise, evidence-backed findings.",
        "Return in English with these sections only:",
        "1) Executive Summary",
        "2) Key Findings",
        "3) Incident Hypotheses",
        "4) IOC Candidates",
        "5) Recommended Next Actions",
        "Keep each finding tied to concrete artifacts (id/category/source/timestamp).",
        "",
        f"Case ID: {case_data.get('case_id')}",
        f"Source: {case_data.get('source_name')} ({case_data.get('source_type')})",
        f"Artifact count: {summary.get('artifact_count')}",
        f"Severity distribution: {json.dumps(summary.get('severity', {}), ensure_ascii=False)}",
        f"Category distribution: {json.dumps(summary.get('category', {}), ensure_ascii=False)}",
        "",
        "Artifacts:",
    ]

    for row in artifacts:
        details = str(row.get("details") or "").replace("\n", " ")
        details = details[:260]
        title = str(row.get("title") or "")[:140]
        lines.append(
            " | ".join(
                [
                    f"severity={row.get('severity')}",
                    f"id={row.get('id')}",
                    f"category={row.get('category')}",
                    f"subcategory={row.get('subcategory')}",
                    f"timestamp={row.get('timestamp')}",
                    f"title={title}",
                    f"details={details}",
                    f"source={row.get('source_file')}",
                ]
            )
        )

    return "\n".join(lines)


def run_local_ollama(case_data: dict[str, Any], model: str = "qwen2.5:14b-q4_K_M") -> dict[str, Any]:
    max_artifacts = max(20, int(os.getenv("LOCAL_ANALYSIS_MAX_ARTIFACTS", "60")))
    prompt = build_case_prompt(case_data, max_artifacts=max_artifacts)
    endpoint = str(os.getenv("OLLAMA_ENDPOINT", "http://127.0.0.1:11434")).rstrip("/")
    timeout_sec = max(60, int(os.getenv("LOCAL_ANALYSIS_TIMEOUT", "360")))
    max_tokens = max(160, int(os.getenv("LOCAL_ANALYSIS_MAX_TOKENS", "480")))
    num_ctx = max(2048, int(os.getenv("LOCAL_ANALYSIS_NUM_CTX", "4096")))

    available_models: list[str] = []
    try:
        tag_resp = requests.get(f"{endpoint}/api/tags", timeout=20)
        if tag_resp.status_code < 300:
            data = tag_resp.json()
            for item in data.get("models", []) or []:
                name = str(item.get("name") or "").strip()
                if name:
                    available_models.append(name)
    except requests.RequestException:
        available_models = []

    requested_model = model
    resolved_model = resolve_ollama_model(requested_model, available_models)
    model_note = ""
    if requested_model != resolved_model:
        model_note = f"Requested model '{requested_model}' not found. Using '{resolved_model}'."

    try:
        data = _ollama_generate(
            endpoint=endpoint,
            model=resolved_model,
            prompt=prompt,
            num_ctx=num_ctx,
            num_predict=max_tokens,
            timeout_sec=timeout_sec,
        )
        retry_note = ""
    except requests.Timeout as exc:
        # Retry once with smaller input/output for low-memory machines.
        small_prompt = build_case_prompt(case_data, max_artifacts=max(20, max_artifacts // 2))
        try:
            data = _ollama_generate(
                endpoint=endpoint,
                model=resolved_model,
                prompt=small_prompt,
                num_ctx=3072,
                num_predict=max(120, max_tokens // 2),
                timeout_sec=max(120, timeout_sec),
            )
            retry_note = "Initial pass timed out; succeeded with lightweight retry profile."
        except requests.RequestException as retry_exc:
            return {
                "ok": False,
                "engine": "ollama",
                "model": resolved_model,
                "model_requested": requested_model,
                "model_note": model_note,
                "available_models": available_models[:40],
                "error": (
                    f"Ollama timeout on both normal and lightweight retries: {retry_exc}\n"
                    f"Endpoint: {endpoint}\n"
                    "Try closing heavy apps, then rerun. You can also set LOCAL_ANALYSIS_MAX_ARTIFACTS=30."
                ),
            }
    except requests.HTTPError as exc:
        body = ""
        try:
            body = (exc.response.text or "")[:1200] if exc.response is not None else ""
        except Exception:
            body = ""
        return {
            "ok": False,
            "engine": "ollama",
            "model": resolved_model,
            "model_requested": requested_model,
            "model_note": model_note,
            "available_models": available_models[:40],
            "error": (
                f"Ollama HTTP error: {body or str(exc)}\n"
                "If model is missing, run: `ollama pull qwen2.5:14b-instruct`."
            ),
        }
    except requests.RequestException as exc:
        return {
            "ok": False,
            "engine": "ollama",
            "model": resolved_model,
            "model_requested": requested_model,
            "model_note": model_note,
            "available_models": available_models[:40],
            "error": (
                f"Ollama connection failed: {exc}\n"
                f"Endpoint: {endpoint}\n"
                "Check if Ollama is running (`ollama serve`) and reachable."
            ),
        }

    final_note = model_note
    if retry_note:
        final_note = f"{model_note} {retry_note}".strip()
    return {
        "ok": True,
        "engine": "ollama",
        "model": resolved_model,
        "model_requested": requested_model,
        "model_note": final_note,
        "available_models": available_models[:40],
        "analysis": data.get("response", ""),
        "raw": data,
    }


def _ollama_generate(
    *,
    endpoint: str,
    model: str,
    prompt: str,
    num_ctx: int,
    num_predict: int,
    timeout_sec: int,
) -> dict[str, Any]:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_ctx": num_ctx,
            "num_predict": num_predict,
        },
    }
    response = requests.post(
        f"{endpoint}/api/generate",
        json=payload,
        timeout=timeout_sec,
    )
    response.raise_for_status()
    return response.json()


def resolve_ollama_model(requested: str, available: list[str]) -> str:
    req = str(requested or "").strip()
    if not req:
        req = "qwen2.5:14b-q4_K_M"
    if not available:
        return req
    if req in available:
        return req
    req_low = req.lower()
    preferred_patterns = []
    if "qwen2.5:14b" in req_low:
        preferred_patterns = [r"^qwen2\.5:14b", r"qwen2\.5:14b", r"qwen2\.5"]
    elif ":" in req_low:
        family = re.escape(req_low.split(":", 1)[0])
        preferred_patterns = [rf"^{family}:", family]
    else:
        preferred_patterns = [re.escape(req_low)]

    for pat in preferred_patterns:
        rx = re.compile(pat)
        for name in available:
            if rx.search(name.lower()):
                return name
    return available[0]


def run_openai(
    case_data: dict[str, Any],
    api_key: str,
    chat_model: str = "gpt-4.1-mini",
    embed_model: str = "text-embedding-3-small",
) -> dict[str, Any]:
    prompt = build_case_prompt(case_data)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    # Primary path for reasoning models
    resp_payload = {
        "model": chat_model,
        "input": [
            {
                "role": "system",
                "content": [
                    {
                        "type": "input_text",
                        "text": "You are a senior DFIR analyst specialized in macOS investigations.",
                    }
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": prompt,
                    }
                ],
            },
        ],
    }
    try:
        resp = requests.post(
            "https://api.openai.com/v1/responses",
            headers=headers,
            json=resp_payload,
            timeout=600,
        )
        if resp.status_code < 300:
            data = resp.json()
            text = extract_response_text(data)
            return {
                "ok": True,
                "engine": "openai",
                "model": chat_model,
                "embed_model": embed_model,
                "analysis": text,
                "raw": data,
            }
    except requests.RequestException as exc:
        return {
            "ok": False,
            "engine": "openai",
            "model": chat_model,
            "embed_model": embed_model,
            "error": f"OpenAI connection failed: {exc}",
        }

    primary_billing_err = extract_billing_error(resp)
    if primary_billing_err:
        return {
            "ok": False,
            "engine": "openai",
            "model": chat_model,
            "embed_model": embed_model,
            "error": primary_billing_err,
        }

    primary_err = ""
    try:
        primary_err = resp.text[:1200]
    except Exception:
        primary_err = "no response body"

    # Fallback path for non-responses compatible deployments.
    chat_payload = {
        "model": chat_model,
        "messages": [
            {
                "role": "system",
                "content": "You are a senior macOS DFIR analyst.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
    }

    try:
        fallback = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=chat_payload,
            timeout=600,
        )
    except requests.RequestException as exc:
        return {
            "ok": False,
            "engine": "openai",
            "model": chat_model,
            "embed_model": embed_model,
            "error": f"OpenAI fallback connection failed: {exc}",
        }

    fallback_billing_err = extract_billing_error(fallback)
    if fallback_billing_err:
        return {
            "ok": False,
            "engine": "openai",
            "model": chat_model,
            "embed_model": embed_model,
            "error": fallback_billing_err,
        }

    if fallback.status_code >= 300:
        return {
            "ok": False,
            "engine": "openai",
            "model": chat_model,
            "embed_model": embed_model,
            "error": (
                f"OpenAI responses error: {resp.status_code} {primary_err}\n"
                f"OpenAI fallback error: {fallback.status_code} {fallback.text[:1200]}"
            ),
        }

    data = fallback.json()
    text = ""
    choices = data.get("choices", [])
    if choices:
        message = choices[0].get("message", {})
        text = message.get("content", "")

    return {
        "ok": True,
        "engine": "openai",
        "model": chat_model,
        "embed_model": embed_model,
        "analysis": text,
        "raw": data,
    }


def extract_billing_error(resp: requests.Response) -> str:
    if resp.status_code != 429:
        return ""
    try:
        payload = resp.json()
    except Exception:
        return ""
    err = payload.get("error") if isinstance(payload, dict) else {}
    if not isinstance(err, dict):
        return ""
    code = str(err.get("code") or "").strip().lower()
    msg = str(err.get("message") or "").strip()
    if code == "billing_not_active" or "billing" in msg.lower():
        return (
            "OpenAI API billing is not active for this key/account. "
            "Enable billing at https://platform.openai.com/settings/organization/billing and retry."
        )
    return ""


def extract_response_text(response_data: dict[str, Any]) -> str:
    if isinstance(response_data.get("output_text"), list):
        chunks = [x for x in response_data.get("output_text") if isinstance(x, str)]
        if chunks:
            return "\n".join(chunks)
    if isinstance(response_data.get("output_text"), str):
        return response_data["output_text"]

    outputs = response_data.get("output", [])
    chunks: list[str] = []
    for item in outputs:
        if not isinstance(item, dict):
            continue
        content = item.get("content", [])
        if not isinstance(content, list):
            continue
        for part in content:
            if not isinstance(part, dict):
                continue
            txt = part.get("text")
            if isinstance(txt, str):
                chunks.append(txt)
    return "\n".join(chunks)


def prioritize_artifacts(artifacts: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    severity_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    ordered = sorted(
        artifacts,
        key=lambda x: (
            severity_rank.get(str(x.get("severity", "low")).lower(), 99),
            str(x.get("timestamp") or ""),
        ),
    )
    return ordered[:limit]
