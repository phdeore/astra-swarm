"""Astra-Swarm tool-use round-trip runner — Day 3."""

from __future__ import annotations

from typing import Any

from anthropic import Anthropic

from .tools import ALL_TOOL_SCHEMAS, dispatch_tool

_client = Anthropic()
_MODEL = "claude-haiku-4-5-20251001"


def run_with_tools(
    user_prompt: str,
    tools: list[dict[str, Any]] | None = None,
    system: str | None = None,
    max_rounds: int = 5,
    max_tokens: int = 1024,
    verbose: bool = False,
) -> dict[str, Any]:
    """Run a tool-use conversation until the model stops asking for tools.

    Returns a dict with:
      - final_text: the model's final answer (or empty if it hit max_rounds)
      - rounds:     how many round trips we ran
      - stop_reason: last stop_reason from the API
      - messages:   full messages array (assistant + tool_result turns) for inspection
    """
    tools = tools if tools is not None else ALL_TOOL_SCHEMAS
    messages: list[dict[str, Any]] = [{"role": "user", "content": user_prompt}]

    for round_num in range(1, max_rounds + 1):
        kwargs: dict[str, Any] = {
            "model": _MODEL,
            "max_tokens": max_tokens,
            "tools": tools,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system

        response = _client.messages.create(**kwargs)

        if verbose:
            print(f"--- round {round_num}: stop_reason={response.stop_reason!r} ---")
            for b in response.content:
                if b.type == "text":
                    print(f"  text: {b.text[:120]}...")
                elif b.type == "tool_use":
                    print(f"  tool_use: {b.name}({b.input})  id={b.id}")

        # Preserve the assistant's response verbatim in the transcript.
        messages.append({"role": "assistant", "content": response.content})

        # If the model didn't ask for a tool, we're done.
        if response.stop_reason != "tool_use":
            final_text = "".join(b.text for b in response.content if b.type == "text")
            return {
                "final_text": final_text,
                "rounds": round_num,
                "stop_reason": response.stop_reason,
                "messages": messages,
            }

        # Otherwise execute every tool_use block and send results back in ONE user turn.
        tool_results: list[dict[str, Any]] = []
        for block in response.content:
            if block.type == "tool_use":
                result_str = dispatch_tool(block.name, block.input)
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,  # MUST match block.id exactly
                        "content": result_str,
                    }
                )
                if verbose:
                    print(f"  tool_result for {block.id}: {result_str[:120]}...")

        messages.append({"role": "user", "content": tool_results})

    return {
        "final_text": "[hit max_rounds without a final answer]",
        "rounds": max_rounds,
        "stop_reason": "max_rounds_exceeded",
        "messages": messages,
    }
