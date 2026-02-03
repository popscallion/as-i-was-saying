# as-i-was-saying

A small CLI that turns Claude or Codex JSONL session logs into a single Markdown transcript.

**Philosophy**
- Human-readable output over clever formatting.
- One renderer, consistent modes, and no silent data loss.
- Resilient to schema changes by preserving unknown blocks.

## Usage

**Interactive picker (Claude by default)**
```bash
as-i-was-saying
```

**Convert a specific file**
```bash
as-i-was-saying path/to/session.jsonl
as-i-was-saying path/to/session.jsonl output.md
```

## Install to PATH (optional)

Use `uv` to install the CLI and add it to your shell PATH:
```bash
uv tool install --editable .
uv tool update-shell
```

Restart your shell after updating PATH. You can also add the tool directory manually:
```bash
uv tool dir
```

## Backends

Claude is the default backend. Codex sessions require `--backend codex`.

```bash
as-i-was-saying --backend codex ~/.codex/sessions/2026/01/27/rollout-...jsonl
```

If you pass a file path under `~/.codex/sessions` or `~/.claude/projects`, the tool will infer the backend automatically.

## Modes

- `chat` (default): text-only, no thinking or tool output.
- `thoughts`: includes thinking and tool usage, omits tool outputs.
- `verbose`: includes all thinking and full tool outputs.

```bash
as-i-was-saying --thoughts path/to/session.jsonl
as-i-was-saying --verbose path/to/session.jsonl
as-i-was-saying --mode verbose path/to/session.jsonl
```

## Redaction

- `--redact`: pattern-based redaction of common identifiers in output.
- `--redact-strict`: more aggressive redaction (may over-redact useful context).
- `--redact-level {standard|strict|none}`: explicit redaction level selection.

Redaction is opt-in and prints loud warnings in the output. It is not guaranteed to catch every secret.

## Data Locations

- Claude: `~/.claude/projects`
- Codex: `~/.codex/sessions`

## Known Limitations

- Codex `reasoning` entries are rendered from the summary when available; encrypted content is not shown.
- If a backend emits a new block type, it will appear as raw JSON until normalization is updated.
- `chat` mode omits tool-only turns (those without text blocks).
- Backend inference is path-based; if logs are moved, pass `--backend` explicitly.

## Privacy Notes

- Fixtures are anonymized, but logs can still contain sensitive data.
- Anonymization is pattern-based and not guaranteed to catch every secret; review before sharing.
- The anonymizer also redacts bare domains, IP addresses, and common token formats, which may over-redact legitimate text.
- Do not publish raw logs; anonymize before sharing or opening a PR.
- Keep fixtures minimal (single short session per backend) and trim large tool outputs.
- If you fork this repo and are not contributing back, keep the fork private.
- If you scrub history, delete any remote tags or branches that still reference pre-scrub commits.
- Anonymized fixtures are not guaranteed safe for public posting.

**Fixture Checklist**
Run these scans before committing fixtures:
```bash
rg -n "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}" tests/fixtures
rg -n "https?://" tests/fixtures | rg -n -v "https?://HOST-"
rg -n "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b" tests/fixtures
rg -n "\\b(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f]{1,4}\\b" tests/fixtures
rg -n "\\b(sk-[A-Za-z0-9]{10,}|sk_live_[A-Za-z0-9]{10,}|gh[opurs]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|A(?:KIA|SIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ya29\\.[0-9A-Za-z_-]+)\\b" tests/fixtures
```

## Development

Testing uses `uv`:
```bash
uv venv
uv pip install -e '.[dev]'
uv run python -m pytest -q
```

Fixtures are anonymized JSONL samples under `tests/fixtures/` with expected outputs.
Regenerate expected outputs with:
```bash
uv run python tools/regenerate_fixtures.py
```

The pre-commit hook runs `uv lock --check`, `pytest`, and privacy scans against `tests/fixtures`.

### History Scrub (if needed)

If you ever need to purge sensitive fixture history, use `git filter-repo` and force-push:

```bash
git filter-repo --path tests/fixtures --invert-paths

git push --force --all
git push --force --tags
```

Then re-add sanitized fixtures and regenerate outputs.

## Credits

Inspired by [simonw/claude-code-transcripts](https://github.com/simonw/claude-code-transcripts).

## License

GPL-3.0-only. See `LICENSE`.
