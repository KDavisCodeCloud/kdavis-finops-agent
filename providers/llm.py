"""Minimal LLM provider seam.

LLM-agnostic per the global non-negotiable, kept intentionally small for
a single-provider Phase 1: one function, one provider, callers never
import the Anthropic SDK directly. If a second provider is ever needed,
it gets added here behind the same complete() signature -- not scattered
across call sites.
"""

import os

import anthropic

_MODEL = "claude-sonnet-4-6"


def complete(system_prompt: str, user_content: str, max_tokens: int = 4096) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError("ANTHROPIC_API_KEY not set")

    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=_MODEL,
        max_tokens=max_tokens,
        system=system_prompt,
        messages=[{"role": "user", "content": user_content}],
    )
    return response.content[0].text
