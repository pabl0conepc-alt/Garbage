"""Language-model client for the AI investigator (catalogue block 7).

Three settings choose the model: ``ai.provider`` (disabled,
openai-compatible or anthropic), ``ai.base_url`` and ``ai.model``. The key, if
the endpoint needs one, is the ``ai`` provider in the local key store.

- openai-compatible covers local servers (Ollama, LM Studio, llama.cpp,
  vLLM, LocalAI) and hosted ones (OpenRouter, OpenAI, Groq, Together, ...):
  POST {base_url}/chat/completions.
- anthropic calls the Messages API: POST {base_url}/v1/messages.

An endpoint on this machine or the local network may use http:// on any
port and is reached directly; any other endpoint must be public https://
and goes through the same guarded fetcher as the connectors. Raw HTTP is used
because GARBAGE ships without third-party packages.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
from typing import Any
from urllib.parse import urlsplit

from . import net
from .db import _connection, setting_value
from .errors import ValidationError
from .intel_keys import get_secret

PROVIDERS = ("disabled", "openai-compatible", "anthropic")
DEFAULT_BASE = {"openai-compatible": "http://localhost:11434/v1", "anthropic": "https://api.anthropic.com"}
ANTHROPIC_VERSION = "2026-10-21"
TIMEOUT_SECONDS = 300.0
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
FETCH = net.fetch


class LLMError(ValueError):
    pass


def api_key(database: str) -> str:
    """The AI key, or the assistant's earlier OpenRouter key."""
    return get_secret(database, "ai") or get_secret(database, "openrouter") or ""


def is_local_endpoint(url: str) -> bool:
    """True for loopback or private-network hosts (the operator's own machine or LAN)."""
    host = (urlsplit(url).hostname or "").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(info[4][0].split("%")[0]) for info in socket.getaddrinfo(host, None)]
        except socket.gaierror:
            return False
    return bool(addresses) and all(address.is_loopback or address.is_private or address.is_link_local for address in addresses)


def validate_endpoint(url: str) -> str:
    url = url.strip().rstrip("/")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise ValidationError("ai.base_url must be an http(s) URL without credentials")
    if parts.scheme == "http" and not is_local_endpoint(url):
        raise ValidationError("ai.base_url may use http:// only for this machine or the local network; use https:// otherwise")
    return url


def config(database: str) -> dict[str, Any]:
    with _connection(database) as connection:
        provider = setting_value(connection, "ai.provider", "disabled") or "disabled"
        base_url = setting_value(connection, "ai.base_url", "") or DEFAULT_BASE.get(provider, "")
        model = setting_value(connection, "ai.model", "")
        legacy_model = setting_value(connection, "assistant.model", "")
    # The assistant was first configured as an OpenRouter key plus a model;
    # that setup keeps working until a provider is chosen in Settings.
    if provider == "disabled" and legacy_model and get_secret(database, "openrouter"):
        provider, base_url, model = "openai-compatible", "https://openrouter.ai/api/v1", legacy_model
    return {
        "provider": provider,
        "base_url": base_url.rstrip("/"),
        "model": model,
        "has_key": bool(api_key(database)),
        "local": bool(base_url) and is_local_endpoint(base_url),
    }


def _post(url: str, headers: dict[str, str], payload: dict[str, Any], fetch: Any = None) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json", **headers}
    if is_local_endpoint(url):
        parts = urlsplit(url)
        connection_class = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
        connection = connection_class(parts.hostname, parts.port, timeout=TIMEOUT_SECONDS)
        try:
            target = parts.path + (f"?{parts.query}" if parts.query else "")
            connection.request("POST", target, body=body, headers=headers)
            response = connection.getresponse()
            status, raw = response.status, response.read(MAX_RESPONSE_BYTES + 1)
        except OSError as exc:
            raise LLMError(f"could not reach the local model server: {exc}") from exc
        finally:
            connection.close()
    else:
        try:
            result = (fetch or FETCH)(url, method="POST", headers=headers, body=body, allowed_hosts=(urlsplit(url).hostname,),
                                      max_bytes=MAX_RESPONSE_BYTES, timeout=TIMEOUT_SECONDS)
        except (net.NetworkError, net.NetworkPolicyError) as exc:
            raise LLMError(str(exc)) from exc
        status, raw = result.status, result.body
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LLMError(f"the model server answered HTTP {status} with a non-JSON body") from exc
    if status >= 400:
        detail = data.get("error") if isinstance(data, dict) else None
        message = detail.get("message") if isinstance(detail, dict) else detail
        known = {401: "the model server refused the key", 402: "the account has no credits left", 429: "the model server rate-limited the request"}
        raise LLMError(f"{known.get(status) or f'the model server answered HTTP {status}'}: {str(message or data)[:300]}")
    return data


def chat(database: str, system: str, messages: list[dict[str, str]], *, max_tokens: int = 4096) -> str:
    """Send a conversation and return the assistant's text."""
    settings = config(database)
    provider, model = settings["provider"], settings["model"]
    if provider == "disabled":
        raise LLMError("no model is configured: choose a provider in Settings")
    if not model:
        raise LLMError("ai.model is empty: set the model name in Settings")
    key = api_key(database)
    base = validate_endpoint(settings["base_url"])
    if provider == "anthropic":
        if not key:
            raise LLMError("the Anthropic API needs a key: save it under API keys → AI model")
        data = _post(
            f"{base}/v1/messages",
            {"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION},
            {"model": model, "max_tokens": max_tokens, "system": system, "messages": messages},
        )
        if data.get("stop_reason") == "refusal":
            raise LLMError("the model declined this request")
        text = "".join(block.get("text", "") for block in data.get("content", []) if isinstance(block, dict) and block.get("type") == "text")
    else:
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        if "openrouter.ai" in base:
            headers.update({"HTTP-Referer": "https://github.com/pabl0conepc-alt/Garbage", "X-Title": "GARBAGE"})
        data = _post(
            f"{base}/chat/completions",
            headers,
            {"model": model, "max_tokens": max_tokens, "messages": [{"role": "system", "content": system}, *messages]},
        )
        choices = data.get("choices") or []
        message = choices[0].get("message", {}) if choices and isinstance(choices[0], dict) else {}
        text = message.get("content") or ""
        if isinstance(text, list):  # some servers return content parts
            text = "".join(part.get("text", "") for part in text if isinstance(part, dict))
    if not text.strip():
        raise LLMError("the model returned an empty answer")
    return text


def _anthropic_messages(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """OpenAI-style chat (system, user, assistant with tool_calls, tool) to Messages API blocks."""
    system_parts: list[str] = []
    converted: list[dict[str, Any]] = []

    def push(role: str, block: dict[str, Any]) -> None:
        if converted and converted[-1]["role"] == role:
            converted[-1]["content"].append(block)
        else:
            converted.append({"role": role, "content": [block]})

    for message in messages:
        role = message.get("role")
        if role == "system":
            system_parts.append(str(message.get("content") or ""))
        elif role == "tool":
            push("user", {"type": "tool_result", "tool_use_id": message.get("tool_call_id", ""), "content": str(message.get("content") or "")})
        elif role == "assistant":
            if message.get("content"):
                push("assistant", {"type": "text", "text": str(message["content"])})
            for call in message.get("tool_calls") or []:
                function = call.get("function") or {}
                try:
                    arguments = json.loads(function.get("arguments") or "{}")
                except json.JSONDecodeError:
                    arguments = {}
                push("assistant", {"type": "tool_use", "id": call.get("id", ""), "name": function.get("name", ""), "input": arguments if isinstance(arguments, dict) else {}})
        else:
            push("user", {"type": "text", "text": str(message.get("content") or "")})
    return "\n\n".join(part for part in system_parts if part), converted


def chat_with_tools(database: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]], *, max_tokens: int = 4000, fetch: Any = None) -> dict[str, Any]:
    """One tool-enabled turn in OpenAI format; returns {"content", "tool_calls"}.

    openai-compatible endpoints take the request as is (local servers need a
    model that supports tools); for Anthropic the conversation and tools are
    translated to the Messages API and the answer back to OpenAI form.
    """
    settings = config(database)
    provider, model = settings["provider"], settings["model"]
    if provider == "disabled" or not model:
        raise LLMError("no model is configured: choose a provider and model in Settings")
    key = api_key(database)
    base = validate_endpoint(settings["base_url"])
    if provider == "anthropic":
        if not key:
            raise LLMError("the Anthropic API needs a key: save it under API keys → AI model")
        system, converted = _anthropic_messages(messages)
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": converted,
            "tools": [
                {"name": tool["function"]["name"], "description": tool["function"].get("description", ""),
                 "input_schema": tool["function"].get("parameters") or {"type": "object", "properties": {}}}
                for tool in tools
            ],
        }
        if system:
            payload["system"] = system
        data = _post(f"{base}/v1/messages", {"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION}, payload, fetch)
        if data.get("stop_reason") == "refusal":
            raise LLMError("the model declined this request")
        blocks = [block for block in data.get("content") or [] if isinstance(block, dict)]
        return {
            "content": "".join(block.get("text", "") for block in blocks if block.get("type") == "text"),
            "tool_calls": [
                {"id": block.get("id", ""), "type": "function",
                 "function": {"name": block.get("name", ""), "arguments": json.dumps(block.get("input") or {}, ensure_ascii=False)}}
                for block in blocks
                if block.get("type") == "tool_use"
            ],
        }
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    if "openrouter.ai" in base:
        headers.update({"HTTP-Referer": "https://github.com/pabl0conepc-alt/Garbage", "X-Title": "GARBAGE"})
    data = _post(f"{base}/chat/completions", headers,
                 {"model": model, "messages": messages, "tools": tools, "tool_choice": "auto", "max_tokens": max_tokens}, fetch)
    choices = data.get("choices") or []
    message = choices[0].get("message") if choices and isinstance(choices[0], dict) else None
    if not isinstance(message, dict):
        raise LLMError("the model server returned an answer without a message")
    return message
