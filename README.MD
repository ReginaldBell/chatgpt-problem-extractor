# ChatGPT Problem Extractor

A hardened, production-ready CLI tool that converts ChatGPT conversation exports into structured problem/solution records with schema validation and optional PII redaction.

## Overview

This tool processes JSON exports from ChatGPT, identifies problem-solution pairs within conversations, and outputs them as validated, structured records. It's designed for building knowledge bases, archiving technical discussions, or preparing ChatGPT data for further analysis—all while protecting sensitive information.

### Key Features

- **Intelligent Problem/Solution Detection** – Uses heuristics (keywords, patterns, code blocks, stack traces) to identify problems and corresponding solutions
- **Schema Validation** – Enforces strict dataclass-based structure with type checking
- **PII Redaction** – Optional masking of emails, AWS keys, JWTs, and high-entropy tokens
- **Conversation Threading** – Properly reconstructs message chains from ChatGPT's tree structure
- **Classification** – Automatically tags problems by domain (networking, programming, database, devops, etc.)
- **Quality Metrics** – Tracks pairing confidence, distance, and solution presence
- **Statistics & Telemetry** – Detailed counts of conversations, messages, and tag distributions
- **Safe File Operations** – Path validation, SHA-256 checksums, and comprehensive error handling

## Installation

### Requirements

- Python 3.8+
- No external dependencies (uses only stdlib)

### Setup

```bash
# Clone or download the project
git clone https://github.com/ReginaldBell/chatgpt-problem-extractor.git
cd chatgpt-problem-extractor

# (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install test dependencies (optional)
pip install pytest
```

## Usage

### Basic Usage

```bash
python extractor.py --input chatgpt_export.json --out out/results.json
```

### Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--input` | `chatgpt_export.json` | Path to ChatGPT export JSON file |
| `--out` | `out/results.json` | Path for output results JSON |
| `--redact` | (disabled) | Enable PII redaction (emails, tokens, AWS keys) |
| `--dummy` | (disabled) | Emit sample output for testing (skips parsing) |
| `--print-sha256` | (disabled) | Print SHA-256 hash of input file |

### Examples

**Extract with redaction enabled:**
```bash
python extractor.py --input chatgpt_export.json --out results.json --redact
```

**Generate dummy output for testing:**
```bash
python extractor.py --dummy --out test_output.json
```

**Check input file integrity:**
```bash
python extractor.py --input chatgpt_export.json --print-sha256
```

## Exporting from ChatGPT

1. Go to ChatGPT's settings (account menu)
2. Select **Data Controls** → **Export your data**
3. Request and download the JSON export
4. Pass the file to this tool

## Output Format

### Result Structure

```json
{
  "schema_version": "1.0",
  "export_source": {
    "source_file": "chatgpt_export.json",
    "generated_at": "2025-01-19T14:32:00-06:00",
    "tool_version": "0.2.0",
    "notes": "Extracted 5 problem-solution pairs from 2 conversations"
  },
  "stats": {
    "conversations_scanned": 2,
    "messages_scanned": 18,
    "records_emitted": 5,
    "records_filtered_out": 0,
    "tag_counts": {
      "networking": 2,
      "programming": 2,
      "database": 1
    }
  },
  "records": [
    {
      "record_id": "prb_conv_001_0",
      "conversation": {
        "conversation_id": "conv_001",
        "title": "Network Setup Help",
        "created_at": "2024-12-15T10:30:00+00:00",
        "updated_at": "2024-12-15T11:45:00+00:00"
      },
      "message_ref": {
        "user_message_id": "msg_user_001",
        "assistant_message_id": "msg_asst_001",
        "user_timestamp": "2024-12-15T10:30:00+00:00",
        "assistant_timestamp": "2024-12-15T10:32:00+00:00"
      },
      "problem": {
        "raw_text": "My ping is not working. Why can't I reach the gateway?",
        "normalized_text": "Cannot reach gateway; ping failing.",
        "signals": {
          "has_question_mark": true,
          "has_code_block": false,
          "has_stack_trace": false,
          "keyword_hits": ["not working", "ping"]
        }
      },
      "solution": {
        "raw_text": "Try running: $ ipconfig /all. Then check your gateway IP and ping it.",
        "solution_type": "steps",
        "artifacts": {
          "includes_code": false,
          "includes_commands": true,
          "includes_numbered_steps": false
        }
      },
      "classification": {
        "tags": ["networking", "infrastructure"],
        "domain": "networking",
        "confidence": 85
      },
      "quality": {
        "is_solved_in_thread": true,
        "pairing_method": "next_assistant_within_k",
        "pair_distance": 1
      },
      "export": {
        "source_file": "chatgpt_export.json",
        "generated_at": "2025-01-19T14:32:00-06:00",
        "tool_version": "0.2.0"
      }
    }
  ]
}
```

### Record Fields Explained

**record_id** – Unique identifier for the problem-solution pair

**conversation** – Reference to the original ChatGPT conversation

**message_ref** – IDs and timestamps of the user problem and assistant solution

**problem** – Details of the identified problem:
- `raw_text` – Full problem text (potentially redacted)
- `normalized_text` – Abbreviated summary
- `signals` – Metadata (question marks, code blocks, keywords found)

**solution** – Details of the identified solution:
- `raw_text` – Full solution text
- `solution_type` – Category (steps, explanation, code, unknown)
- `artifacts` – What the solution contains (code, commands, structured steps)

**classification** – Domain categorization:
- `domain` – Primary category (networking, programming, database, devops, system, web, other)
- `tags` – Multiple applicable tags (e.g., ["networking", "infrastructure"])
- `confidence` – 0-100 score indicating classification certainty

**quality** – Metrics about the pairing:
- `is_solved_in_thread` – Was a solution found in the same conversation?
- `pairing_method` – How the solution was matched to the problem
- `pair_distance` – Number of messages between problem and solution

## How It Works

### 1. Message Parsing

The tool reconstructs ChatGPT's conversation tree structure by walking from the leaf node up through parent pointers to the root, preserving chronological order.

### 2. Problem Detection

Uses a scoring system based on:
- Question marks (+0.25)
- Problem keywords (error, bug, crash, etc.) (+0.2 per hit, max +0.6)
- Code blocks (+0.15)
- Stack traces (+0.2)
- Pattern matches (questions, tracebacks) (+0.15)

Messages scoring ≥ 0.3 are classified as problems.

### 3. Solution Detection

Scores responses based on:
- Message length (>100 chars: +0.2, >500 chars: +0.1)
- Solution keywords (try, install, configure, etc.) (+0.1 per hit, max +0.4)
- Code blocks (+0.25)
- Shell commands (+0.2)
- Numbered/bulleted steps (+0.2)

Messages scoring ≥ 0.3 are classified as solutions.

### 4. Problem-Solution Pairing

For each detected problem, the tool searches the next 5 messages for an assistant response that scores as a solution. This proximity-based approach captures the most relevant answer.

### 5. Classification

Classifies problems into domains (networking, programming, database, devops, system, web) by counting keyword matches. Confidence is proportional to keyword hits.

### 6. Redaction (Optional)

When enabled, masks:
- **Emails** – `user@example.com` → `[REDACTED_EMAIL]`
- **AWS Keys** – `AKIA1234567890ABCDEF` → `[REDACTED_AWS_KEY]`
- **JWTs** – `eyJhbGc...` → `[REDACTED_JWT]`
- **High-entropy tokens** – `abc123def456...` → `[REDACTED_TOKEN]`

Respects a 50KB scanning limit per message for performance.

## Testing

Run the test suite:

```bash
pytest tests/test_extraction.py -v
pytest tests/test_pipeline.py -v
```

### Test Coverage

- Message extraction and parsing
- Problem/solution detection thresholds
- Code block and stack trace detection
- Keyword matching and scoring
- Classification by domain
- Problem-solution pairing logic
- Full extraction pipeline
- JSON serialization and schema validation
- Redaction logic

## Architecture

### Core Modules

**extractor.py** – Main pipeline:
- `Redactor` – PII masking logic
- `ProblemDetector` – Problem identification and scoring
- `SolutionDetector` – Solution identification and scoring
- `Classifier` – Domain and tag classification
- `extract_from_chatgpt_export()` – Main extraction function

**schema.py** – Data structures:
- Frozen dataclasses for immutability
- Type hints for validation
- Custom `to_dict()` serialization with tuple→list conversion for JSON

### Key Design Decisions

1. **Dataclasses** – Type safety and validation at instantiation
2. **Frozen dataclasses** – Immutability prevents accidental modifications
3. **Scoring functions** – Flexible thresholds allow tuning sensitivity
4. **Tuple-to-list conversion** – Maintains schema strictness while allowing JSON output
5. **Path validation** – Prevents directory traversal attacks
6. **Streaming parsing** – Handles large exports efficiently

## Configuration & Tuning

### Adjust Detection Sensitivity

Edit thresholds in `ProblemDetector.is_problem()` and `SolutionDetector.is_solution()`:

```python
# More permissive (catches more problems, more false positives)
problem_detector.is_problem(text, threshold=0.2)

# More strict (catches fewer problems, higher precision)
problem_detector.is_problem(text, threshold=0.5)
```

### Adjust Pairing Distance

In `extract_problem_solution_pairs()`, change `max_pair_distance`:

```python
# Look further ahead for solutions (default: 5)
pairs = extract_problem_solution_pairs(..., max_pair_distance=10)
```

### Extend Classification Domains

Add rules to `Classifier.__init__()`:

```python
self.rules["machine_learning"] = {
    "keywords": ["tensorflow", "pytorch", "model", "training"],
    "tags": ("ml", "ai"),
}
```

## Security Considerations

- **Path Traversal Protection** – Validates all file paths against project root
- **Safe JSON Parsing** – Explicit encoding and error handling
- **PII Redaction** – Sanitizes sensitive data before output
- **Permission Checking** – Fails gracefully on permission errors
- **Bounded Scanning** – Limits text processing to prevent DoS

## Error Handling

The tool exits with specific codes:

| Code | Reason |
|------|--------|
| 0 | Success |
| 1 | Unexpected error |
| 2 | File not found |
| 3 | Permission denied |
| 4 | JSON decode error |
| 5 | Validation error |

All errors are logged to stderr with detailed messages.

## Limitations & Known Issues

1. **Single-turn accuracy** – Detection relies on conversation structure; complex back-and-forth may miss context
2. **Language English-centric** – Keywords and patterns are English-focused
3. **Schema evolution** – ChatGPT export format may change; tool may need updates
4. **Confidence scores** – Classification confidence is keyword-count based, not ML-based
5. **Redaction scope** – Scans only first 50KB of each message for performance

## Performance

- **Typical dataset** – 100 conversations (~5000 messages): ~2 seconds
- **Memory** – O(n) where n is total message count
- **Output size** – ~10-20% of input size (depending on solution density)

## Contributing

Contributions welcome! Areas for improvement:

- [ ] Machine learning-based classification
- [ ] Multi-language support
- [ ] Advanced redaction (custom patterns)
- [ ] Incremental processing (resume from checkpoint)
- [ ] Web UI for browsing results
- [ ] Integration with knowledge base systems

## License

MIT License – See LICENSE file

## Support & Issues

- **Report bugs** – Open an issue on GitHub
- **Request features** – Discuss in Discussions
- **Questions?** – Check the FAQ in the wiki

---

**Last Updated:** January 2025  
**Version:** 0.2.0  
**Author:** Reginald Bell