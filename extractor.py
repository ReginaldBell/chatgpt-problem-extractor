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
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass

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

# ============================================================================
# SETUP & CONSTANTS
# ============================================================================

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

MAX_SCAN_CHARS = 50_000

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
AWS_ACCESS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
GENERIC_TOKEN_RE = re.compile(r"\b[a-zA-Z0-9_\-]{32,}\b")

PROJECT_ROOT = Path(__file__).resolve().parent

# ============================================================================
# REDACTION
# ============================================================================

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

# ============================================================================
# FILE I/O
# ============================================================================

def resolve_under_root(path_str: str, root: Path) -> Path:
    """Resolve path and ensure it stays under project root."""
    p = (root / path_str).resolve() if not Path(path_str).is_absolute() else Path(path_str).resolve()
    if root not in p.parents and p != root:
        raise ValueError(f"Refusing path outside project root: {p}")
    return p

def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Compute SHA-256 of file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def read_json_safe(path: Path) -> dict:
    """Read JSON file with error handling."""
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except PermissionError as e:
        raise PermissionError(f"Permission denied reading: {path}") from e
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in {path}: {e.msg}", e.doc, e.pos)

def write_json_safe(path: Path, obj: dict) -> None:
    """Write JSON file with error handling."""
    try:
        with path.open("w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
    except PermissionError as e:
        raise PermissionError(f"Permission denied writing: {path}") from e

def ensure_out_dir(path: str) -> None:
    """Create output directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)

def now_iso() -> str:
    """Get current time in ISO format."""
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

# ============================================================================
# PROBLEM & SOLUTION DETECTION
# ============================================================================

class ProblemDetector:
    """Identifies messages that contain user problems/questions."""
    
    def __init__(self):
        self.problem_keywords = {
            "error", "not working", "failing", "broken", "crash", "bug",
            "issue", "problem", "help", "question", "how do", "what is",
            "can't", "cannot", "doesn't", "not able", "unable", "stuck",
            "confused", "unclear", "doesn't work", "fail", "exception"
        }
        self.problem_patterns = [
            re.compile(r"error:\s*\w+", re.I),
            re.compile(r"(traceback|stack trace|stacktrace)", re.I),
            re.compile(r"(what|how|why|where|when)\s+(\w+\s+){0,5}(do|can|is|should)", re.I),
        ]
    
    def has_code_block(self, text: str) -> bool:
        """Check for code blocks (markdown or raw)."""
        if not text:
            return False
        return bool(re.search(r"```|^    \S", text, re.M))
    
    def has_stack_trace(self, text: str) -> bool:
        """Check for error traces/tracebacks."""
        if not text:
            return False
        return bool(re.search(
            r"(traceback|stacktrace|at line \d+|file .*line|\.py:\d+)",
            text, re.I
        ))
    
    def count_keyword_hits(self, text: str, keywords: Set[str]) -> Tuple[str, ...]:
        """Find which keywords appear in text. Returns tuple (important for schema)."""
        if not text:
            return ()
        text_lower = text.lower()
        found = tuple(kw for kw in keywords if kw in text_lower)
        return found
    
    def score_problem(self, text: str) -> float:
        """Score likelihood this is a problem message (0.0-1.0).
        
        Scoring:
        - Question mark: +0.25
        - Each keyword hit: +0.2 (up to 3 keywords max +0.6)
        - Code block: +0.15
        - Stack trace: +0.2
        - Pattern match: +0.15
        
        Total can exceed 1.0 but is capped at 1.0
        """
        if not text or not text.strip():
            return 0.0
        
        score = 0.0
        
        # Question mark is strong signal
        if "?" in text:
            score += 0.25
        
        # Keyword matches - each keyword adds 0.2, up to 3 keywords
        hits = self.count_keyword_hits(text, self.problem_keywords)
        if hits:
            score += min(len(hits) * 0.2, 0.6)  # More generous: 0.2 per hit
        
        # Code block or error
        if self.has_code_block(text):
            score += 0.15
        if self.has_stack_trace(text):
            score += 0.2
        
        # Pattern matches
        for pattern in self.problem_patterns:
            if pattern.search(text):
                score += 0.15
                break  # Only count once
        
        return min(score, 1.0)
    
    def is_problem(self, text: str, threshold: float = 0.3) -> bool:
        """Determine if message is a problem."""
        return self.score_problem(text) >= threshold


class SolutionDetector:
    """Identifies assistant responses that likely contain solutions."""
    
    def __init__(self):
        self.solution_keywords = {
            "try", "check", "verify", "install", "use", "call",
            "set", "configure", "run", "execute", "add", "remove",
            "solution", "fixed", "resolved", "worked", "should",
            "need", "required", "step", "first", "then", "finally"
        }
        self.command_patterns = [
            re.compile(r"^\s*[$#]\s+\S+", re.M),  # shell prompts
            re.compile(r"(npm|pip|apt|curl|docker|git)\s+\w+", re.I),
        ]
    
    def has_code_block(self, text: str) -> bool:
        """Check for code blocks."""
        if not text:
            return False
        return bool(re.search(r"```|^    \S", text, re.M))
    
    def has_commands(self, text: str) -> bool:
        """Check for shell commands."""
        if not text:
            return False
        for pattern in self.command_patterns:
            if pattern.search(text):
                return True
        return False
    
    def has_numbered_steps(self, text: str) -> bool:
        """Check for numbered or bulleted instructions."""
        if not text:
            return False
        return bool(re.search(r"^\s*(\d+\.|[-*•])\s+", text, re.M))
    
    def score_solution(self, text: str) -> float:
        """Score likelihood this is a solution (0.0-1.0)."""
        if not text or not text.strip():
            return 0.0
        
        score = 0.0
        
        # Length (solutions tend to be longer)
        if len(text) > 100:
            score += 0.2
        if len(text) > 500:
            score += 0.1
        
        # Solution keywords
        text_lower = text.lower()
        hits = sum(1 for kw in self.solution_keywords if kw in text_lower)
        score += min(hits * 0.1, 0.4)
        
        # Actionable artifacts
        if self.has_code_block(text):
            score += 0.25
        if self.has_commands(text):
            score += 0.2
        if self.has_numbered_steps(text):
            score += 0.2
        
        return min(score, 1.0)
    
    def is_solution(self, text: str, threshold: float = 0.3) -> bool:
        """Determine if message is a solution."""
        return self.score_solution(text) >= threshold


class Classifier:
    """Classifies problems into domains and tags."""
    
    def __init__(self):
        # Domain/tag rules (keyword -> (domain, tags))
        self.rules = {
            "networking": {
                "keywords": ["network", "ip", "dns", "subnet", "ping", "connection", "port", "firewall"],
                "tags": ("networking", "infrastructure"),
            },
            "programming": {
                "keywords": ["code", "syntax", "function", "variable", "loop", "array", "object", "class"],
                "tags": ("programming", "debugging"),
            },
            "web": {
                "keywords": ["html", "css", "javascript", "react", "node", "http", "api", "rest"],
                "tags": ("web-development", "frontend"),
            },
            "database": {
                "keywords": ["sql", "database", "query", "table", "index", "transaction", "postgres", "mysql"],
                "tags": ("database", "backend"),
            },
            "devops": {
                "keywords": ["docker", "kubernetes", "deploy", "ci/cd", "pipeline", "terraform"],
                "tags": ("devops", "infrastructure"),
            },
            "system": {
                "keywords": ["linux", "windows", "macos", "shell", "bash", "permission", "user", "system"],
                "tags": ("system-admin", "infrastructure"),
            },
        }
    
    def classify(self, text: str) -> Classification:
        """Classify problem into domain and tags."""
        text_lower = text.lower()
        found_tags = set()
        domain_scores = {}
        
        for domain, config in self.rules.items():
            matches = sum(1 for kw in config["keywords"] if kw in text_lower)
            if matches > 0:
                domain_scores[domain] = matches
                found_tags.update(config["tags"])
        
        # Determine primary domain and confidence
        if domain_scores:
            domain = max(domain_scores, key=domain_scores.get)
            confidence = min(domain_scores[domain] * 25, 100)
        else:
            domain = "other"
            confidence = 0
        
        tags = tuple(sorted(found_tags)) if found_tags else ("uncategorized",)
        
        return Classification(tags=tags, domain=domain, confidence=int(confidence))

# ============================================================================
# MESSAGE PARSING
# ============================================================================

@dataclass
class Message:
    """Parsed message from ChatGPT export."""
    id: str
    role: str  # "user" or "assistant"
    text: str
    timestamp: Optional[int]
    
    def get_iso_timestamp(self) -> Optional[str]:
        """Convert timestamp to ISO format."""
        if not self.timestamp:
            return None
        return datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat()


def extract_text_from_message(msg_obj: dict) -> Optional[str]:
    """Extract text content from ChatGPT message object."""
    if not msg_obj:
        return None
    # Accept both message dicts and content dicts
    content = msg_obj.get("content") if isinstance(msg_obj, dict) else None
    if content and isinstance(content, dict):
        # msg_obj is a message dict
        pass
    elif isinstance(msg_obj, dict) and "content_type" in msg_obj:
        # msg_obj is already a content dict
        content = msg_obj
    else:
        return None

    if content.get("content_type") != "text":
        return None

    parts = content.get("parts", [])
    if not parts:
        return None

    # Join parts (usually just one)
    text = "".join(str(p) for p in parts if isinstance(p, str))
    return text.strip() if text else None


def get_conversation_history(mapping: dict, current_node_id: Optional[str]) -> List[Message]:
    """
    Walk message tree from leaf (current_node) up to root (parent=None).
    Returns messages in chronological order.
    """
    path = []
    visited = set()
    curr = current_node_id
    
    while curr and curr in mapping and curr not in visited:
        visited.add(curr)
        node = mapping[curr]
        msg_obj = node.get("message")
        
        if msg_obj:
            text = extract_text_from_message(msg_obj)
            role = msg_obj.get("author", {}).get("role")
            timestamp = msg_obj.get("create_time")
            
            if text and role:
                path.insert(0, Message(
                    id=msg_obj.get("id", curr),
                    role=role,
                    text=text,
                    timestamp=timestamp
                ))
        
        # Move to parent
        curr = node.get("parent")
    
    return path

# ============================================================================
# EXTRACTION PIPELINE
# ============================================================================

def extract_problem_solution_pairs(
    messages: List[Message],
    problem_detector: ProblemDetector,
    solution_detector: SolutionDetector,
    classifier: Classifier,
    redactor: Redactor,
    max_pair_distance: int = 5
) -> List[Dict]:
    """Find problem-solution pairs in message sequence."""
    pairs = []
    
    for i, msg in enumerate(messages):
        if msg.role != "user":
            continue
        
        # Check if this is a problem
        if not problem_detector.is_problem(msg.text):
            continue
        
        # Look for solution in next k assistant messages
        solution_msg = None
        pair_distance = -1
        
        for j in range(i + 1, min(i + max_pair_distance + 1, len(messages))):
            if messages[j].role == "assistant":
                if solution_detector.is_solution(messages[j].text):
                    solution_msg = messages[j]
                    pair_distance = j - i
                    break
        
        # Create pair record
        problem_text = redactor.mask(msg.text)
        solution_text = redactor.mask(solution_msg.text) if solution_msg else None
        
        classification = classifier.classify(problem_text)
        
        problem_signals = ProblemSignals(
            has_question_mark="?" in msg.text,
            has_code_block=problem_detector.has_code_block(msg.text),
            has_stack_trace=problem_detector.has_stack_trace(msg.text),
            keyword_hits=problem_detector.count_keyword_hits(msg.text, problem_detector.problem_keywords),
        )
        
        problem = ProblemBlock(
            raw_text=problem_text,
            normalized_text=msg.text[:200],
            signals=problem_signals,
        )
        
        solution_artifacts = SolutionArtifacts(
            includes_code=solution_detector.has_code_block(solution_text) if solution_text else False,
            includes_commands=solution_detector.has_commands(solution_text) if solution_text else False,
            includes_numbered_steps=solution_detector.has_numbered_steps(solution_text) if solution_text else False,
        )
        
        solution = SolutionBlock(
            raw_text=solution_text,
            solution_type="explanation" if solution_text else "unknown",
            artifacts=solution_artifacts,
        )
        
        quality = Quality(
            is_solved_in_thread=solution_msg is not None,
            pairing_method="next_assistant_within_k",
            pair_distance=pair_distance,
        )
        
        pairs.append({
            "problem_msg": msg,
            "solution_msg": solution_msg,
            "problem": problem,
            "solution": solution,
            "classification": classification,
            "quality": quality,
        })
    
    return pairs


def extract_from_chatgpt_export(
    data: dict,
    redactor: Redactor,
    max_pair_distance: int = 5
) -> Tuple[List[ProblemRecord], Stats]:
    """Main extraction function. Returns (records, stats)."""
    
    problem_detector = ProblemDetector()
    solution_detector = SolutionDetector()
    classifier = Classifier()
    
    records = []
    stats = Stats()
    
    # Validate input structure
    conversations = data if isinstance(data, list) else data.get("conversations", [])
    if not isinstance(conversations, list):
        log.warning("Input is not a list of conversations")
        return records, stats
    
    for conv_idx, conv in enumerate(conversations):
        if not isinstance(conv, dict):
            log.warning(f"Conversation {conv_idx} is not a dict, skipping")
            continue
        
        stats.conversations_scanned += 1
        
        conv_id = conv.get("id", f"conv_{conv_idx}")
        conv_title = conv.get("title", "(untitled)")
        conv_created = conv.get("create_time")
        conv_updated = conv.get("update_time")
        
        # Walk message tree from leaf to root
        mapping = conv.get("mapping", {})
        root_id = conv.get("current_node") or (next(iter(mapping), None) if mapping else None)
        
        messages = get_conversation_history(mapping, root_id)
        stats.messages_scanned += len(messages)
        
        if not messages:
            continue
        
        # Extract pairs
        pairs = extract_problem_solution_pairs(
            messages, problem_detector, solution_detector, classifier,
            redactor, max_pair_distance
        )
        
        for pair_idx, pair in enumerate(pairs):
            record_id = f"prb_{conv_id}_{pair_idx}"
            
            # Convert timestamps safely to ISO format
            created_dt = datetime.fromtimestamp(conv_created, tz=timezone.utc) if conv_created else None
            updated_dt = datetime.fromtimestamp(conv_updated, tz=timezone.utc) if conv_updated else None
            
            convo_ref = ConversationRef(
                conversation_id=conv_id,
                title=conv_title,
                created_at=created_dt.isoformat() if created_dt else None,
                updated_at=updated_dt.isoformat() if updated_dt else None,
            )
            
            msg_ref = MessageRef(
                user_message_id=pair["problem_msg"].id,
                assistant_message_id=pair["solution_msg"].id if pair["solution_msg"] else None,
                user_timestamp=pair["problem_msg"].get_iso_timestamp(),
                assistant_timestamp=pair["solution_msg"].get_iso_timestamp() if pair["solution_msg"] else None,
            )
            
            record = ProblemRecord(
                record_id=record_id,
                conversation=convo_ref,
                message_ref=msg_ref,
                problem=pair["problem"],
                solution=pair["solution"],
                classification=pair["classification"],
                quality=pair["quality"],
                export=ExportSource(
                    source_file="chatgpt_export.json",
                    generated_at=datetime.now(timezone.utc).isoformat(),
                    tool_version="0.2.0",
                ),
            )
            
            records.append(record)
            stats.records_emitted += 1
            
            # Track tag counts
            for tag in pair["classification"].tags:
                stats.tag_counts[tag] = stats.tag_counts.get(tag, 0) + 1
    
    return records, stats

# ============================================================================
# DUMMY OUTPUT
# ============================================================================

def build_dummy_result(input_path: str, redactor: Redactor = None) -> ExtractionResult:
    """Build a dummy result for testing."""
    export = ExportSource(
        source_file=input_path,
        generated_at=now_iso(),
        tool_version="0.2.0",
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
        tags=("networking",),
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

# ============================================================================
# UTILITIES
# ============================================================================

def warn_if_empty(convos_scanned: int, msgs_scanned: int, records: int) -> None:
    """Warn if extraction produced empty results."""
    if convos_scanned > 0 and msgs_scanned == 0:
        print("WARN: Conversations found but zero messages parsed. Export schema may have changed.", file=sys.stderr)
    if msgs_scanned > 0 and records == 0:
        print("WARN: Messages parsed but zero problem records emitted. Heuristics may be too strict.", file=sys.stderr)

# ============================================================================
# MAIN
# ============================================================================

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
            # Load ChatGPT export
            export_data = read_json_safe(in_path)
            
            # Run extraction pipeline
            records, stats = extract_from_chatgpt_export(export_data, redactor)
            
            # Build result with extracted data
            result = ExtractionResult(
                export_source=ExportSource(
                    source_file=str(in_path),
                    generated_at=now_iso(),
                    tool_version="0.2.0",
                    notes=f"Extracted {len(records)} problem-solution pairs from {stats.conversations_scanned} conversations"
                ),
                stats=stats,
                records=records,
            )

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