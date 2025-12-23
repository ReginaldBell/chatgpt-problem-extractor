from __future__ import annotations
import logging
import sys

def setup_logger(name: str, level: int = logging.INFO):
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger

log = setup_logger("schema")

from dataclasses import dataclass, asdict, field, is_dataclass
from typing import Any, Dict, List, Optional


def _normalize_for_json(obj: Any) -> Any:
    if is_dataclass(obj):
        return _normalize_for_json(asdict(obj))
    if isinstance(obj, dict):
        return {str(k): _normalize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize_for_json(v) for v in obj]
    if isinstance(obj, set):
        return sorted(_normalize_for_json(v) for v in obj)
    if isinstance(obj, tuple):
        return [_normalize_for_json(v) for v in obj]
    return obj


@dataclass(frozen=True)
class ExportSource:
    source_file: str
    generated_at: str
    tool_version: str
    notes: str = ""


@dataclass
class Stats:
    conversations_scanned: int = 0
    messages_scanned: int = 0
    records_emitted: int = 0
    records_filtered_out: int = 0
    tag_counts: Dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class ConversationRef:
    conversation_id: str
    title: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass(frozen=True)
class MessageRef:
    user_message_id: str
    assistant_message_id: Optional[str] = None
    user_timestamp: Optional[str] = None
    assistant_timestamp: Optional[str] = None


@dataclass(frozen=True)
class ProblemSignals:
    has_question_mark: bool = False
    has_code_block: bool = False
    has_stack_trace: bool = False
    keyword_hits: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProblemBlock:
    raw_text: str
    normalized_text: str = ""
    signals: ProblemSignals = field(default_factory=ProblemSignals)

    def __post_init__(self):
        if not self.raw_text.strip():
            raise ValueError("ProblemBlock.raw_text cannot be empty")


@dataclass(frozen=True)
class SolutionArtifacts:
    includes_code: bool = False
    includes_commands: bool = False
    includes_numbered_steps: bool = False


@dataclass(frozen=True)
class SolutionBlock:
    raw_text: Optional[str] = None
    solution_type: str = "unknown"  # e.g., "steps", "explanation", "code", "unknown"
    artifacts: SolutionArtifacts = field(default_factory=SolutionArtifacts)


@dataclass(frozen=True)
class Classification:
    tags: tuple[str, ...] = ()
    domain: str = "other"
    confidence: int = 0  # 0-100

    def __post_init__(self):
        if not (0 <= self.confidence <= 100):
            raise ValueError("confidence must be between 0 and 100")


@dataclass(frozen=True)
class Quality:
    is_solved_in_thread: bool = False
    pairing_method: str = "unknown"   # e.g., "next_assistant_within_k"
    pair_distance: int = -1           # how many messages ahead the solution was found


@dataclass(frozen=True)
class ProblemRecord:
    record_id: str
    conversation: ConversationRef
    message_ref: MessageRef
    problem: ProblemBlock
    solution: SolutionBlock
    classification: Classification
    quality: Quality
    export: ExportSource


@dataclass
class ExtractionResult:

    export_source: ExportSource
    stats: Stats = field(default_factory=Stats)
    records: List[ProblemRecord] = field(default_factory=list)
    schema_version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        return _normalize_for_json(self)
