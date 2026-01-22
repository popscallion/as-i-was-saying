import json
import sys
import os
import argparse
import glob
from pathlib import Path
from datetime import datetime

# Mode documentation for both CLI help and Output headers
MODE_DESCRIPTIONS = {
    "chat": "Conversation text only. No thinking blocks or tool details.",
    "thoughts": "Logic flow. Includes thinking and tool usage. Tool outputs are summarized.",
    "verbose": "Full record. Includes all thinking, tool usage, and full tool outputs."
}

def format_timestamp(ts_str):
    try:
        # Handle formats like 2026-01-21T21:13:13.514Z
        if not ts_str: return ""
        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return ts_str

def get_session_summary(filepath):
    """Read first user message from session file"""
    try:
        with open(filepath, 'r') as f:
            for line in f:
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    if data.get("type") == "user":
                        # Extract content
                        msg = data.get("message", {})
                        content = msg.get("content", "")
                        
                        text = ""
                        if isinstance(content, str):
                            text = content
                        elif isinstance(content, list):
                            for block in content:
                                if block.get("type") == "text":
                                    text += block.get("text", "") + " "
                        
                        text = text.strip()
                        # Skip empty or system-like messages (starting with <)
                        if text and not text.startswith("<"):
                            return text
                except:
                    continue
    except:
        pass
    return filepath.name

def find_recent_sessions(limit=20):
    """Scan ~/.claude/projects for recent .jsonl sessions"""
    base_dir = Path.home() / ".claude" / "projects"
    if not base_dir.exists():
        return []

    sessions = []
    # Recursively find all jsonl files
    for path in base_dir.rglob("*.jsonl"):
        if "agent-" in path.name:
            continue
            
        try:
            stat = path.stat()
            sessions.append({
                "path": path,
                "mtime": stat.st_mtime,
                "size": stat.st_size
            })
        except OSError:
            continue
            
    # Sort by mtime descending
    sessions.sort(key=lambda x: x["mtime"], reverse=True)
    recent = sessions[:limit]
    
    # Enrich with summaries
    for s in recent:
        raw_summary = get_session_summary(s["path"])
        # Truncate and clean
        clean_summary = raw_summary.replace('\n', ' ').strip()
        if len(clean_summary) > 60:
            clean_summary = clean_summary[:57] + "..."
        s["summary"] = clean_summary
        
    return recent

def select_session():
    """Interactive session selector"""
    sessions = find_recent_sessions()
    
    if not sessions:
        print("No Claude sessions found in ~/.claude/projects", file=sys.stderr)
        sys.exit(1)
        
    print("\nRecent Claude Sessions:", file=sys.stderr)
    
    for i, s in enumerate(sessions):
        dt = datetime.fromtimestamp(s['mtime']).strftime('%Y-%m-%d %H:%M')
        size_kb = f"{s['size'] / 1024:.0f}KB"
        
        # Format: 1. 2026-01-21 12:00 (50KB)  Summary text...
        print(f"{i+1:2}. {dt} ({size_kb:>5})  {s['summary']}", file=sys.stderr)
        
    while True:
        try:
            sys.stderr.write("\nSelect session (1-20) or 'q' to quit: ")
            sys.stderr.flush()
            choice = sys.stdin.readline().strip().lower()
            
            if choice == 'q':
                sys.exit(0)
            
            if not choice:
                continue
                
            idx = int(choice) - 1
            if 0 <= idx < len(sessions):
                return str(sessions[idx]['path'])
            else:
                sys.stderr.write("Invalid number.\n")
        except ValueError:
             sys.stderr.write("Please enter a number.\n")
        except KeyboardInterrupt:
            sys.exit(0)

def render_block(block, mode):
    b_type = block.get("type")
    
    # --chat mode (DEFAULT): Skip everything except text
    if mode == "chat":
        if b_type == "text":
            return block.get("text", "")
        return ""

    # Common for Thoughts and Verbose
    if b_type == "text":
        return block.get("text", "")
        
    elif b_type == "thinking":
        thinking = block.get("thinking", "")
        return "> **Thinking**\n" + "\n".join(f"> {line}" for line in thinking.splitlines())
        
    elif b_type == "tool_use":
        name = block.get("name")
        input_data = block.get("input")
        return f"**Tool Use: `{name}`**\n```json\n{json.dumps(input_data, indent=2)}\n```"
        
    elif b_type == "tool_result":
        # In Thoughts mode, suppress the actual content
        if mode == "thoughts":
            is_error = block.get("is_error", False)
            status = "Error" if is_error else "Success"
            return f"_[Tool Result: {status} - Output Omitted]_"
            
        # In Verbose mode, show full content
        if mode == "verbose":
            content = block.get("content", "")
            is_error = block.get("is_error", False)
            header = "**Tool Result (Error)**" if is_error else "**Tool Result**"
            
            # content can be string or list of blocks
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
        
    return ""

def convert(filepath, output_file=None, mode="chat"):
    if not os.path.exists(filepath):
        print(f"Error: File not found {filepath}")
        return

    out = sys.stdout
    if output_file:
        out = open(output_file, 'w')

    try:
        out.write(f"# Transcript: {os.path.basename(filepath)}\n")
        out.write(f"Mode: {mode}\n")
        out.write(f"Description: {MODE_DESCRIPTIONS.get(mode, '')}\n\n")
        
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    data = json.loads(line)
                except:
                    continue
                
                row_type = data.get("type")
                # Filter for core message types
                if row_type not in ["user", "assistant"]:
                    continue
                
                timestamp = format_timestamp(data.get("timestamp", ""))
                message_obj = data.get("message", {})
                role = message_obj.get("role") or row_type
                content = message_obj.get("content")
                
                # Buffer content to see if we have anything to print
                rendered_blocks = []
                if isinstance(content, str):
                    rendered_blocks.append(content)
                elif isinstance(content, list):
                    for block in content:
                        rendered = render_block(block, mode)
                        if rendered:
                            rendered_blocks.append(rendered)
                            
                # If nothing to show (e.g. Chat mode hiding a tool-only turn), skip the header
                if not rendered_blocks:
                    continue
                
                out.write(f"## {role.title()} ({timestamp})\n\n")
                out.write("\n\n".join(rendered_blocks))
                out.write("\n\n---\n\n")
                
    finally:
        if output_file and out is not sys.stdout:
            out.close()
            # Only print success message if writing to file
            print(f"Successfully converted to {output_file} ({mode} mode)")

def main():
    desc = "Convert Claude Code JSONL to Markdown.\n\nModes:\n"
    for m, d in MODE_DESCRIPTIONS.items():
        desc += f"  {m:<10} {d}\n"
        
    parser = argparse.ArgumentParser(
        description=desc,
        formatter_class=argparse.RawTextHelpFormatter
    )
    # Make input_file optional
    parser.add_argument("input_file", nargs="?", help="Path to input .jsonl file")
    parser.add_argument("output_file", nargs="?", help="Path to output .md file (optional)")
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--thoughts", action="store_true", help="Enable 'thoughts' mode (Logic flow, summarized outputs)")
    group.add_argument("--verbose", action="store_true", help="Enable 'verbose' mode (Full record with outputs)")
    
    args = parser.parse_args()
    
    # Determine mode
    mode = "chat"
    if args.verbose:
        mode = "verbose"
    elif args.thoughts:
        mode = "thoughts"
    
    # Handle missing input file -> Interactive mode
    if not args.input_file:
        if sys.stdin.isatty():
            args.input_file = select_session()
        else:
            print("Error: No input file provided and not running interactively.", file=sys.stderr)
            sys.exit(1)
            
    convert(args.input_file, args.output_file, mode)

if __name__ == "__main__":
    main()