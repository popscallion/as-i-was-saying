import argparse
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from redaction import Redactor

# Mode documentation for both CLI help and Output headers
MODE_DESCRIPTIONS = {
    "chat": "Conversation text only. No thinking blocks or tool details.",
    "thoughts": "Logic flow. Includes thinking and tool usage. Tool outputs are summarized.",
    "verbose": "Full record. Includes all thinking, tool usage, and full tool outputs.",
}

SUPPORTED_BACKENDS = ("claude", "codex")


def format_timestamp(ts_str: str) -> str:
    try:
        # Handle formats like 2026-01-21T21:13:13.514Z
        if not ts_str:
            return ""
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts_str


def get_base_dir(backend: str) -> Path:
    if backend == "codex":
        return Path.home() / ".codex" / "sessions"
    return Path.home() / ".claude" / "projects"


def infer_backend_from_path(path: str) -> Optional[str]:
    if not path:
        return None
    expanded = str(Path(path).expanduser())
    codex_base = str(get_base_dir("codex"))
    claude_base = str(get_base_dir("claude"))
    if expanded.startswith(codex_base):
        return "codex"
    if expanded.startswith(claude_base):
        return "claude"
    return None


def extract_text_from_blocks(blocks: List[Dict[str, Any]]) -> str:
    parts: List[str] = []
    for block in blocks:
        if block.get("type") == "text":
            text = block.get("text", "")
            if text:
                parts.append(text)
    return " ".join(parts).strip()


def get_session_summary(filepath: str, backend: str) -> Optional[str]:
    """Read first user message from session file"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    continue

                events = normalize_event(data, backend)
                for event in events:
                    if event.get("role") != "user":
                        continue
                    text = extract_text_from_blocks(event.get("blocks", []))
                    if text and not text.startswith("<"):
                        return text
    except Exception:
        pass
    return None


def find_recent_sessions(backend: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Scan backend directory for recent .jsonl sessions"""
    base_dir = get_base_dir(backend)
    if not base_dir.exists():
        return []

    sessions: List[Dict[str, Any]] = []
    for path in base_dir.rglob("*.jsonl"):
        if backend == "claude" and "agent-" in path.name:
            continue

        try:
            stat = path.stat()
            sessions.append({"path": path, "mtime": stat.st_mtime, "size": stat.st_size})
        except OSError:
            continue

    sessions.sort(key=lambda x: x["mtime"], reverse=True)

    valid_sessions: List[Dict[str, Any]] = []
    candidates = sessions[: limit * 2]

    for s in candidates:
        raw_summary = get_session_summary(str(s["path"]), backend)
        if not raw_summary:
            continue

        clean_summary = raw_summary.replace("\n", " ").strip()
        if len(clean_summary) > 60:
            clean_summary = clean_summary[:57] + "..."
        s["summary"] = clean_summary
        valid_sessions.append(s)

        if len(valid_sessions) >= limit:
            break

    return valid_sessions


def select_session(backend: str) -> str:
    """Interactive session selector"""
    sessions = find_recent_sessions(backend)

    if not sessions:
        print(f"No {backend.title()} sessions found in {get_base_dir(backend)}", file=sys.stderr)
        sys.exit(1)

    print(f"\nRecent {backend.title()} Sessions:", file=sys.stderr)

    for i, s in enumerate(sessions):
        dt = datetime.fromtimestamp(s["mtime"]).strftime("%Y-%m-%d %H:%M")
        size_kb = f"{s['size'] / 1024:.0f}KB"
        print(f"{i+1:2}. {dt} ({size_kb:>5})  {s['summary']}", file=sys.stderr)

    while True:
        try:
            sys.stderr.write("\nSelect session (1-20) or 'q' to quit: ")
            sys.stderr.flush()
            choice = sys.stdin.readline().strip().lower()

            if choice == "q":
                sys.exit(0)

            if not choice:
                continue

            idx = int(choice) - 1
            if 0 <= idx < len(sessions):
                return str(sessions[idx]["path"])
            sys.stderr.write("Invalid number.\n")
        except ValueError:
            sys.stderr.write("Please enter a number.\n")
        except KeyboardInterrupt:
            sys.exit(0)


def render_block(block: Dict[str, Any], mode: str, redactor: Optional[Redactor] = None) -> str:
    b_type = block.get("type")

    # --chat mode (DEFAULT): Skip everything except text
    if mode == "chat":
        if b_type == "text":
            text = block.get("text", "")
            if redactor:
                text = redactor.redact(text)
            return text
        return ""

    # Common for Thoughts and Verbose
    if b_type == "text":
        text = block.get("text", "")
        if redactor:
            text = redactor.redact(text)
        return text

    if b_type == "thinking":
        thinking = block.get("thinking", "")
        if redactor:
            thinking = redactor.redact(thinking)
        return "> **Thinking**\n" + "\n".join(f"> {line}" for line in thinking.splitlines())

    if b_type == "tool_use":
        name = block.get("name")
        input_data = block.get("input")
        if redactor:
            input_data = redactor.redact(input_data)
        return f"**Tool Use: `{name}`**\n```json\n{json.dumps(input_data, indent=2)}\n```"

    if b_type == "tool_result":
        if mode == "thoughts":
            is_error = block.get("is_error", False)
            status = "Error" if is_error else "Success"
            return f"_[Tool Result: {status} - Output Omitted]_"

        if mode == "verbose":
            content = block.get("content", "")
            if redactor:
                content = redactor.redact(content)
            is_error = block.get("is_error", False)
            header = "**Tool Result (Error)**" if is_error else "**Tool Result**"

            text_content = ""
            if isinstance(content, str):
                text_content = content
            elif isinstance(content, list):
                parts = []
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        parts.append(item.get("text", ""))
                    elif isinstance(item, dict) and item.get("type") == "image":
                        parts.append("[Image Data Omitted]")
                    else:
                        parts.append(str(item))
                text_content = "\n".join(parts)
            else:
                text_content = str(content)

            return f"{header}\n```text\n{text_content}\n```"

    if b_type == "meta":
        label = block.get("label", "Meta")
        content = block.get("content", {})
        if redactor:
            content = redactor.redact(content)
        return f"**{label}**\n```json\n{json.dumps(content, indent=2)}\n```"

    if b_type == "unknown":
        source = block.get("source", "unknown")
        raw = block.get("raw", {})
        if redactor:
            raw = redactor.redact(raw)
        return f"**Unknown Block: `{source}`**\n```json\n{json.dumps(raw, indent=2)}\n```"

    return ""


def normalize_event(raw: Dict[str, Any], backend: str) -> List[Dict[str, Any]]:
    if backend == "codex":
        return normalize_codex_event(raw)
    return normalize_claude_event(raw)


def normalize_claude_event(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    row_type = raw.get("type")
    if row_type not in {"user", "assistant"}:
        return []

    msg = raw.get("message", {})
    role = msg.get("role") or row_type
    content = msg.get("content")

    blocks: List[Dict[str, Any]] = []
    if isinstance(content, str):
        blocks.append({"type": "text", "text": content})
    elif isinstance(content, list):
        for block in content:
            if isinstance(block, dict):
                blocks.append(block)

    if not blocks:
        return []

    return [
        {
            "role": role,
            "timestamp": raw.get("timestamp", ""),
            "blocks": blocks,
        }
    ]


def _parse_json_maybe(text: str) -> Any:
    if not isinstance(text, str):
        return text
    text = text.strip()
    if not text:
        return text
    try:
        return json.loads(text)
    except Exception:
        return text


def _codex_text_from_items(items: Iterable[Dict[str, Any]]) -> str:
    parts: List[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        text = item.get("text")
        if text:
            parts.append(text)
    return "\n".join(parts).strip()


def _codex_summary_text(summary: Any) -> str:
    if isinstance(summary, list):
        parts: List[str] = []
        for item in summary:
            if isinstance(item, dict) and item.get("text"):
                parts.append(item.get("text"))
            else:
                parts.append(str(item))
        return "\n".join(parts).strip()
    if isinstance(summary, str):
        return summary
    return ""


def normalize_codex_event(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    row_type = raw.get("type")
    payload = raw.get("payload", {})
    timestamp = raw.get("timestamp", "")

    if row_type == "session_meta":
        return [
            {
                "role": "meta",
                "timestamp": timestamp or payload.get("timestamp", ""),
                "blocks": [
                    {"type": "meta", "label": "Session Meta", "content": payload}
                ],
            }
        ]

    if row_type == "turn_context":
        return [
            {
                "role": "meta",
                "timestamp": timestamp,
                "blocks": [
                    {"type": "meta", "label": "Turn Context", "content": payload}
                ],
            }
        ]

    if row_type == "event_msg":
        msg_type = payload.get("type")
        text = payload.get("text") or payload.get("message") or ""

        if msg_type == "user_message":
            return [
                {
                    "role": "user",
                    "timestamp": timestamp,
                    "blocks": [{"type": "text", "text": text}],
                }
            ]

        if msg_type == "agent_message":
            return [
                {
                    "role": "assistant",
                    "timestamp": timestamp,
                    "blocks": [{"type": "text", "text": text}],
                }
            ]

        if msg_type == "agent_reasoning":
            return [
                {
                    "role": "assistant",
                    "timestamp": timestamp,
                    "blocks": [{"type": "thinking", "thinking": text}],
                }
            ]

        if msg_type == "token_count":
            return [
                {
                    "role": "meta",
                    "timestamp": timestamp,
                    "blocks": [
                        {"type": "meta", "label": "Token Count", "content": payload}
                    ],
                }
            ]

        return [
            {
                "role": "meta",
                "timestamp": timestamp,
                "blocks": [
                    {"type": "unknown", "source": "event_msg", "raw": payload}
                ],
            }
        ]

    if row_type != "response_item":
        return []

    item_type = payload.get("type")

    if item_type == "message":
        content = payload.get("content")
        role = payload.get("role")
        if not isinstance(content, list):
            return []

        if role:
            text = _codex_text_from_items(content)
            if not text:
                return []
            return [
                {
                    "role": role,
                    "timestamp": timestamp,
                    "blocks": [{"type": "text", "text": text}],
                }
            ]

        events: List[Dict[str, Any]] = []
        for item in content:
            if not isinstance(item, dict):
                continue
            text = item.get("text", "")
            if not text:
                continue
            item_role = "assistant"
            if item.get("type") == "input_text":
                item_role = "user"
            elif item.get("type") == "output_text":
                item_role = "assistant"
            events.append(
                {
                    "role": item_role,
                    "timestamp": timestamp,
                    "blocks": [{"type": "text", "text": text}],
                }
            )
        return events

    if item_type == "function_call":
        role = payload.get("role") or "assistant"
        input_data = _parse_json_maybe(payload.get("arguments", ""))
        return [
            {
                "role": role,
                "timestamp": timestamp,
                "blocks": [
                    {
                        "type": "tool_use",
                        "name": payload.get("name"),
                        "input": input_data,
                    }
                ],
            }
        ]

    if item_type == "function_call_output":
        return [
            {
                "role": "assistant",
                "timestamp": timestamp,
                "blocks": [
                    {"type": "tool_result", "content": payload.get("output", "")}
                ],
            }
        ]

    if item_type == "reasoning":
        thinking = _codex_summary_text(payload.get("summary"))
        if not thinking:
            thinking = "[Reasoning summary unavailable]"
        return [
            {
                "role": "assistant",
                "timestamp": timestamp,
                "blocks": [{"type": "thinking", "thinking": thinking}],
            }
        ]

    return [
        {
            "role": "meta",
            "timestamp": timestamp,
            "blocks": [
                {"type": "unknown", "source": f"response_item:{item_type}", "raw": payload}
            ],
        }
    ]


def convert(
    filepath: str,
    output_file: Optional[str] = None,
    mode: str = "chat",
    backend: str = "claude",
    redaction: str = "none",
) -> None:
    """Convert a JSONL session into Markdown.

    redaction: "none" | "standard" | "strict"
    """
    if not os.path.exists(filepath):
        print(f"Error: File not found {filepath}")
        return

    out = sys.stdout
    if output_file:
        out = open(output_file, "w", encoding="utf-8")

    redactor: Optional[Redactor] = None
    if redaction in {"standard", "strict"}:
        redactor = Redactor(strict=redaction == "strict")

    try:
        out.write(f"# Transcript: {os.path.basename(filepath)}\n")
        out.write(f"Mode: {mode}\n")
        out.write(f"Description: {MODE_DESCRIPTIONS.get(mode, '')}\n\n")
        if redactor:
            out.write(f"Redaction: {redaction}\n")
            out.write("WARNING: Redaction enabled (pattern-based; not guaranteed safe to share).\n")
            if redaction == "strict":
                out.write("WARNING: Strict redaction may over-redact and remove useful context.\n")
            out.write("\n")

        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    continue

                events = normalize_event(data, backend)
                for event in events:
                    blocks = event.get("blocks", [])
                    rendered_blocks: List[str] = []

                    for block in blocks:
                        rendered = render_block(block, mode, redactor)
                        if rendered:
                            rendered_blocks.append(rendered)

                    if not rendered_blocks:
                        continue

                    role = event.get("role", "")
                    timestamp = format_timestamp(event.get("timestamp", ""))
                    out.write(f"## {role.title()} ({timestamp})\n\n")
                    out.write("\n\n".join(rendered_blocks))
                    out.write("\n\n---\n\n")

    finally:
        if output_file and out is not sys.stdout:
            out.close()
            print(f"Successfully converted to {output_file} ({mode} mode)")


def main() -> None:
    desc = "Convert Claude or Codex JSONL to Markdown.\n\n"
    desc += "Run without arguments to select a recent session interactively.\n\n"
    desc += "Modes:\n"
    for m, d in MODE_DESCRIPTIONS.items():
        desc += f"  {m:<10} {d}\n"

    parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("input_file", nargs="?", help="Path to input .jsonl file")
    parser.add_argument("output_file", nargs="?", help="Path to output .md file (optional)")

    parser.add_argument(
        "--backend",
        choices=SUPPORTED_BACKENDS,
        default="claude",
        help="Select backend (default: claude)",
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--mode",
        choices=["chat", "thoughts", "verbose"],
        help="Select rendering mode (default: chat)",
    )
    mode_group.add_argument("--thoughts", action="store_true", help="Enable 'thoughts' mode (Logic flow, summarized outputs)")
    mode_group.add_argument("--verbose", action="store_true", help="Enable 'verbose' mode (Full record with outputs)")

    redaction_group = parser.add_mutually_exclusive_group()
    redaction_group.add_argument(
        "--redact",
        action="store_true",
        help="Enable pattern-based redaction in output (not guaranteed safe)",
    )
    redaction_group.add_argument(
        "--redact-strict",
        action="store_true",
        help="Enable aggressive redaction (may over-redact useful context)",
    )
    redaction_group.add_argument(
        "--redact-level",
        choices=["standard", "strict", "none"],
        help="Select redaction level (standard|strict|none)",
    )

    args = parser.parse_args()

    mode = "chat"
    if args.mode:
        mode = args.mode
    elif args.verbose:
        mode = "verbose"
    elif args.thoughts:
        mode = "thoughts"

    redaction = "none"
    if args.redact_level:
        if args.redact_level == "standard":
            redaction = "standard"
        elif args.redact_level == "strict":
            redaction = "strict"
        else:
            redaction = "none"
    elif args.redact_strict:
        redaction = "strict"
    elif args.redact:
        redaction = "standard"

    backend = args.backend

    if args.input_file:
        inferred = infer_backend_from_path(args.input_file)
        if inferred and inferred != backend:
            backend = inferred

    if not args.input_file:
        if sys.stdin.isatty():
            args.input_file = select_session(backend)
        else:
            print("Error: No input file provided and not running interactively.", file=sys.stderr)
            sys.exit(1)

    convert(args.input_file, args.output_file, mode, backend, redaction)


if __name__ == "__main__":
    main()
