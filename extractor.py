
# === Standard library imports ===
import argparse
import hashlib
import json
import logging
import os
import re
import sys
from pathlib import Path
from datetime import datetime, timezone

# === Local imports ===
from schema import (
    Classification,
    ConversationRef,
    ExportSource,
    ExtractionResult,
    MessageRef,
    ProblemBlock,
    ProblemRecord,
    ProblemSignals,
    Quality,
    SolutionArtifacts,
    SolutionBlock,
    Stats,
)

def setup_logger(name: str, level: int = logging.INFO):
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger

log = setup_logger("telemetry_engine")


# Consolidated, type-safe Redactor
class Redactor:
    """Consolidated redaction logic for emails, AWS keys, JWTs, and high-entropy tokens."""
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.patterns = {
            "EMAIL": EMAIL_RE,
            "AWS_KEY": AWS_ACCESS_KEY_RE,
            "JWT": JWT_RE,
        }

    def _mask_token(self, m: re.Match) -> str:
        s = m.group(0)
        has_alpha = any(c.isalpha() for c in s)
        has_digit = any(c.isdigit() for c in s)
        return "[REDACTED_TOKEN]" if (has_alpha and has_digit) else s

    def mask(self, text: str) -> str:
        if not self.enabled or not text:
            return text
        t = text[:MAX_SCAN_CHARS]
        for label, pattern in self.patterns.items():
            t = pattern.sub(f"[REDACTED_{label}]", t)
        t = GENERIC_TOKEN_RE.sub(self._mask_token, t)
        if len(text) > MAX_SCAN_CHARS:
            t += "\n[TRUNCATED_FOR_SAFETY]"
        return t

# === Standard library imports ===
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable
from datetime import datetime, timezone

# === Third-party imports ===
# (none)

# === Local imports ===
from schema import (
    Classification,
    ConversationRef,
    ExportSource,
    ExtractionResult,
    MessageRef,
    ProblemBlock,
    ProblemRecord,
    ProblemSignals,
    Quality,
    SolutionArtifacts,
    SolutionBlock,
    Stats,
)

# Example pattern lists for demonstration (replace with your actual patterns/rules)
PROBLEM_PATTERNS = [r"ping fails", r"not working"]
TAG_RULES = {"networking": [r"ip", r"subnet"]}
PROBLEM_RE = [re.compile(p, re.I) for p in PROBLEM_PATTERNS]
TAG_RE = {k: [re.compile(p, re.I) for p in v] for k, v in TAG_RULES.items()}

MAX_SCAN_CHARS = 50_000  # prevents regex on insane blobs

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
AWS_ACCESS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
GENERIC_TOKEN_RE = re.compile(r"\b[a-zA-Z0-9_\-]{32,}\b")  # conservative; still catches many keys

PROJECT_ROOT = Path(__file__).resolve().parent


def warn_if_empty(convos_scanned: int, msgs_scanned: int, records: int) -> None:
    if convos_scanned > 0 and msgs_scanned == 0:
        print("WARN: Conversations found but zero messages parsed. Export schema may have changed.", file=sys.stderr)
    if msgs_scanned > 0 and records == 0:
        print("WARN: Messages parsed but zero problem records emitted. Heuristics may be too strict.", file=sys.stderr)
def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
def read_json_safe(path: Path) -> any:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except PermissionError as e:
        raise PermissionError(f"Permission denied reading: {path}") from e
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in {path}: {e.msg}", e.doc, e.pos)

def write_json_safe(path: Path, obj: any) -> None:
    try:
        with path.open("w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
    except PermissionError as e:
        raise PermissionError(f"Permission denied writing: {path}") from e
import hashlib
import sys
from pathlib import Path
from typing import Iterable
PROJECT_ROOT = Path(__file__).resolve().parent

def resolve_under_root(path_str: str, root: Path) -> Path:
    p = (root / path_str).resolve() if not Path(path_str).is_absolute() else Path(path_str).resolve()
    # require output to stay under project root
    if root not in p.parents and p != root:
        raise ValueError(f"Refusing path outside project root: {p}")
    return p
import argparse
import json
import os
from datetime import datetime, timezone

from schema import (
    Classification,
    ConversationRef,
    ExportSource,
    ExtractionResult,
    MessageRef,
    ProblemBlock,
    ProblemRecord,
    ProblemSignals,
    Quality,
    SolutionArtifacts,
    SolutionBlock,
    Stats,
)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def ensure_out_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)




def build_dummy_result(input_path: str, redactor: 'Redactor' = None) -> ExtractionResult:
    export = ExportSource(
        source_file=input_path,
        generated_at=now_iso(),
        tool_version="0.1.0",
        notes="dummy emission check",
    )

    stats = Stats(
        conversations_scanned=0,
        messages_scanned=0,
        records_emitted=1,
        records_filtered_out=0,
        tag_counts={"other": 1},
    )

    convo = ConversationRef(
        conversation_id="demo_convo",
        title="Demo Conversation",
        created_at=None,
        updated_at=None,
    )

    msg_ref = MessageRef(
        user_message_id="demo_user_msg",
        assistant_message_id="demo_asst_msg",
        user_timestamp=None,
        assistant_timestamp=None,
    )

    raw_problem = "my pings are not going through"
    processed_text = redactor.mask(raw_problem) if redactor else raw_problem
    problem = ProblemBlock(
        raw_text=processed_text,
        normalized_text="Ping fails; no connectivity between endpoints.",
        signals=ProblemSignals(
            has_question_mark=False,
            has_code_block=False,
            has_stack_trace=False,
            keyword_hits=("ping", "not working"),
        ),
    )

    solution = SolutionBlock(
        raw_text="Check IP, subnet mask, default gateway, and cabling/ports.",
        solution_type="steps",
        artifacts=SolutionArtifacts(
            includes_code=False,
            includes_commands=False,
            includes_numbered_steps=False,
        ),
    )

    classification = Classification(
        tags=("networking",),  # tuple for immutability
        domain="networking",
        confidence=75,
    )

    quality = Quality(
        is_solved_in_thread=False,
        pairing_method="dummy",
        pair_distance=1,
    )

    record = ProblemRecord(
        record_id="prb_000001",
        conversation=convo,
        message_ref=msg_ref,
        problem=problem,
        solution=solution,
        classification=classification,
        quality=quality,
        export=export,
    )

    result = ExtractionResult(
        export_source=export,
        stats=stats,
        records=[record],
    )

    return result



def main():
    ap = argparse.ArgumentParser(description="ChatGPT Problem Extractor")
    ap.add_argument("--input", default="chatgpt_export.json", help="ChatGPT export JSON path")
    ap.add_argument("--out", default="out/results.json", help="Output results JSON path")
    ap.add_argument("--dummy", action="store_true", help="Emit dummy output instead of parsing input")
    ap.add_argument("--redact", action="store_true", help="Redact emails/tokens before writing output")
    ap.add_argument("--print-sha256", action="store_true", help="Print SHA-256 of input file")
    args = ap.parse_args()

    try:
        in_path = resolve_under_root(args.input, PROJECT_ROOT) if not Path(args.input).is_absolute() else Path(args.input)
        out_path = resolve_under_root(args.out, PROJECT_ROOT)
        ensure_out_dir(out_path.parent)

        if args.print_sha256:
            print(f"Input SHA-256: {sha256_file(in_path)}")

        redactor = Redactor(enabled=args.redact)
        if args.dummy:
            result = build_dummy_result(str(in_path), redactor=redactor)
        else:
            raise NotImplementedError("Real extraction not wired yet")

        write_json_safe(out_path, result.to_dict())

        print(f"Wrote {out_path}")
        print(f"Conversations scanned: {result.stats.conversations_scanned}")
        print(f"Messages scanned: {result.stats.messages_scanned}")
        print(f"Records emitted: {result.stats.records_emitted}")
        print(f"Filtered out: {result.stats.records_filtered_out}")
        print(f"Tag counts: {result.stats.tag_counts}")

        warn_if_empty(result.stats.conversations_scanned, result.stats.messages_scanned, result.stats.records_emitted)

    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    except PermissionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(3)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to decode JSON: {e}", file=sys.stderr)
        sys.exit(4)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(5)
    except Exception as e:
        print(f"ERROR: Unexpected failure: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
