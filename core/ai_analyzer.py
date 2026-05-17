"""
LLM Integration for AI-powered anomaly analysis.
Only triggered for high-risk events (score > 0.9).
Anonymizes sensitive data before sending to external APIs.
"""

import json
import os
import re
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, ValidationError
from dotenv import load_dotenv

# Load .env from project root
load_dotenv(Path(__file__).parent.parent / ".env")


class AIAnalysisResult(BaseModel):
    RISK_LEVEL: str
    EXPLANATION: str
    LOG_COMMAND: str


SUPPORTED_PROVIDERS = {
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "model_env": "LLM_MODEL",
        "default_model": "meta-llama/llama-3.1-70b-instruct",
        "api_key_env": "OPENROUTER_API_KEY",
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "model_env": "LLM_MODEL",
        "default_model": "llama-3.1-70b-versatile",
        "api_key_env": "GROQ_API_KEY",
    },
}


def _anonymize_text(text: str) -> str:
    """
    Anonymize usernames, internal IPs, and hostnames.
    Replaces sensitive patterns with generic placeholders.
    """
    # Replace internal IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    ip_pattern = r"\b(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b"
    text = re.sub(ip_pattern, "[INTERNAL_IP]", text)

    # Replace common username patterns
    user_pattern = r"\b([a-zA-Z_][a-zA-Z0-9_-]{2,15})\b"
    common_users = os.getenv("USER", "")
    if common_users:
        text = text.replace(common_users, "[USERNAME]")

    # Replace home directory paths
    home = os.path.expanduser("~")
    text = text.replace(home, "/home/[USER]")

    return text


def _build_analysis_prompt(
    detection_result: dict[str, Any],
) -> str:
    """Build a structured prompt for LLM analysis."""
    anomalies = detection_result.get("anomalies", {})
    process_anomalies = anomalies.get("process", [])
    port_anomalies = anomalies.get("ports", [])
    security_threats = anomalies.get("security_threats", [])

    anomaly_details = ""
    if security_threats:
        anomaly_details += "\nSECURITY THREATS (CRITICAL):\n"
        for threat in security_threats:
            anomaly_details += f"  - [!] {threat.get('details', str(threat))}\n"

    if process_anomalies:
        anomaly_details += "\nProcess Anomalies:\n"
        for anomaly in process_anomalies[:10]:
            anomaly_details += f"  - {anomaly.get('details', str(anomaly))}\n"

    if port_anomalies:
        anomaly_details += "\nPort Anomalies:\n"
        for anomaly in port_anomalies[:10]:
            anomaly_details += f"  - {anomaly.get('details', str(anomaly))}\n"

    system_metrics = detection_result.get("system_metrics", {})

    prompt = f"""
You are a Senior Linux Security Architect (OpenCode Security Master). 
Analyze the following anomaly report from a CachyOS (Arch-based) system.

System State:
- Risk Score: {detection_result.get('risk_score', 0)}
- CPU Usage: {system_metrics.get('cpu_percent', 0)}%
- Memory Usage: {system_metrics.get('memory_percent', 0)}%
- Active Processes: {system_metrics.get('process_count', 0)}
- Load Average: {system_metrics.get('load_avg_1', 0)} / {system_metrics.get('load_avg_5', 0)} / {system_metrics.get('load_avg_15', 0)}
{anomaly_details}

Instructions:
1. Identify if the 'SECURITY THREATS' are known hacker patterns (Reverse Shell, SUID abuse, Persistence).
2. Distinguish between normal CachyOS boosters and suspicious activity.
3. Provide a clear, technical investigation command.

Provide your analysis as a JSON object with exactly these fields:
- RISK_LEVEL: One of LOW, MEDIUM, HIGH, CRITICAL
- EXPLANATION: A concise (2-3 sentences) explanation focusing on the most critical threat.
- LOG_COMMAND: The exact bash command to investigate the root cause (e.g., ps auxwwf, ss -atnp, lsof -p <PID>).

Return ONLY valid JSON.
"""
    return _anonymize_text(prompt)


def _get_provider_config() -> dict[str, str] | None:
    """Detect available LLM provider from environment."""
    for provider_name, config in SUPPORTED_PROVIDERS.items():
        api_key = os.getenv(config["api_key_env"])
        if api_key:
            model = os.getenv(config["model_env"]) or config["default_model"]
            return {
                "provider": provider_name,
                "api_key": api_key,
                "base_url": config["base_url"],
                "model": model,
            }
    return None


async def analyze_with_ai(
    detection_result: dict[str, Any],
    provider: str | None = None,
) -> AIAnalysisResult | None:
    """
    Send anonymized anomaly data to LLM for analysis.
    Only triggered for critical risk scores (>0.9).
    """
    config = _get_provider_config()
    if not config:
        return None

    if provider and provider in SUPPORTED_PROVIDERS:
        provider_config = SUPPORTED_PROVIDERS[provider]
        api_key = os.getenv(provider_config["api_key_env"])
        if api_key:
            model = os.getenv(provider_config["model_env"]) or provider_config["default_model"]
            config = {
                "provider": provider,
                "api_key": api_key,
                "base_url": provider_config["base_url"],
                "model": model,
            }

    prompt = _build_analysis_prompt(detection_result)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{config['base_url']}/chat/completions",
                headers={
                    "Authorization": f"Bearer {config['api_key']}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": config["model"],
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are a Linux system security analyst. "
                                "Respond with JSON only."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.3,
                    "max_tokens": 500,
                },
            )

            if response.status_code != 200:
                print(f"[AI Error] HTTP {response.status_code}: {response.text[:300]}")
                return None

            data = response.json()
            content = data["choices"][0]["message"]["content"]

            json_match = re.search(r"\{.*\}", content, re.DOTALL)
            if json_match:
                result_json = json.loads(json_match.group())
                return AIAnalysisResult(**result_json)

            return None

    except (httpx.RequestError, ValidationError, KeyError, json.JSONDecodeError) as e:
        print(f"[AI Error] {type(e).__name__}: {e}")
        return None
