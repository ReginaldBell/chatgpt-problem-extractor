import json
from extractor import Redactor, build_dummy_result
from schema import ExtractionResult

def test_redaction_and_schema():
    print("--- Starting Validation ---")
    
    # 1. Test Redactor Logic
    redactor = Redactor(enabled=True)
    sensitive_email = "test@example.com"
    dirty_text = f"My email is {sensitive_email} and my key is AKIA1234567890ABCDEF"
    clean_text = redactor.mask(dirty_text)
    
    # FIX: Logic check - ensure the original secret is GONE
    assert "[REDACTED_EMAIL]" in clean_text
    assert "[REDACTED_AWS_KEY]" in clean_text
    assert sensitive_email not in clean_text  # This confirms actual redaction
    print("✅ Redaction Logic: PASS")

    # 2. Test Schema Integrity (Standard Mode Compliance)
    # This will fail if you use lists [] instead of tuples () in ProblemSignals
    try:
        result = build_dummy_result("test_input.json", redactor=redactor)
        print("✅ Schema Instantiation: PASS")
    except TypeError as e:
        print(f"❌ Schema Instantiation: FAIL (Type Mismatch: {e})")
        return

    # 3. Test JSON Serialization (Ensuring no drift in output)
    data_dict = result.to_dict()
    assert data_dict["schema_version"] == "1.0"
    assert isinstance(data_dict["records"][0]["problem"]["signals"]["keyword_hits"], list) # JSON converts tuples to lists
    print("✅ JSON Serialization: PASS")
    
    print("--- All Systems Go ---")

if __name__ == "__main__":
    test_redaction_and_schema()
