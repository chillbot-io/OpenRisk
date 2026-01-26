#!/usr/bin/env python3
"""Test script for OpenLabels Client API."""

import sys
import tempfile
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from openlabels import Client
from openlabels.core.scorer import ScoringResult, RiskTier
from openlabels.adapters.base import Entity, NormalizedContext, NormalizedInput


def test_score_text_with_ssn():
    """Test scoring text containing SSN."""
    print("Test 1: score_text with SSN")
    client = Client()
    result = client.score_text("Patient SSN: 123-45-6789")

    assert isinstance(result, ScoringResult), "Should return ScoringResult"
    assert result.score > 0, "Score should be positive for SSN"
    assert result.tier in RiskTier, "Tier should be a RiskTier"
    print(f"  Score: {result.score}, Tier: {result.tier.value}")
    print("  PASSED\n")


def test_score_text_with_credit_card():
    """Test scoring text containing credit card."""
    print("Test 2: score_text with credit card")
    client = Client()
    result = client.score_text("Card: 4532015112830366")  # Valid Luhn checksum

    assert isinstance(result, ScoringResult), "Should return ScoringResult"
    assert result.score > 0, "Score should be positive for credit card"
    print(f"  Score: {result.score}, Tier: {result.tier.value}")
    print("  PASSED\n")


def test_score_text_empty():
    """Test scoring empty text."""
    print("Test 3: score_text with empty content")
    client = Client()
    result = client.score_text("Hello, this is just a normal message.")

    assert isinstance(result, ScoringResult), "Should return ScoringResult"
    assert result.score == 0, f"Score should be 0 for no PII, got {result.score}"
    assert result.tier == RiskTier.MINIMAL, "Tier should be MINIMAL"
    print(f"  Score: {result.score}, Tier: {result.tier.value}")
    print("  PASSED\n")


def test_score_text_with_exposure():
    """Test that exposure affects score."""
    print("Test 4: score_text with different exposure levels")
    client = Client()

    text = "SSN: 123-45-6789"

    private_result = client.score_text(text, exposure="PRIVATE")
    public_result = client.score_text(text, exposure="PUBLIC")

    assert public_result.score >= private_result.score, \
        "Public exposure should have higher or equal score"
    print(f"  Private: {private_result.score}, Public: {public_result.score}")
    print("  PASSED\n")


def test_score_file():
    """Test scoring a file."""
    print("Test 5: score_file")
    client = Client()

    # Create a temporary file with sensitive data
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("Patient: John Doe\n")
        f.write("SSN: 123-45-6789\n")
        f.write("Email: john.doe@example.com\n")
        temp_path = f.name

    try:
        result = client.score_file(temp_path)
        assert isinstance(result, ScoringResult), "Should return ScoringResult"
        assert result.score > 0, "Score should be positive"
        print(f"  Score: {result.score}, Tier: {result.tier.value}")
        print(f"  Categories: {result.categories}")
        print("  PASSED\n")
    finally:
        Path(temp_path).unlink()


def test_score_file_not_found():
    """Test scoring a non-existent file raises error."""
    print("Test 6: score_file with non-existent file")
    client = Client()

    try:
        client.score_file("/nonexistent/path/file.txt")
        assert False, "Should have raised FileNotFoundError"
    except FileNotFoundError:
        print("  Correctly raised FileNotFoundError")
        print("  PASSED\n")


def test_score_from_adapters():
    """Test scoring from adapter outputs."""
    print("Test 7: score_from_adapters")
    client = Client()

    # Create mock normalized input
    entities = [
        Entity(type="SSN", count=1, confidence=0.95, source="test"),
        Entity(type="EMAIL", count=2, confidence=0.90, source="test"),
    ]
    context = NormalizedContext(
        exposure="INTERNAL",
        encryption="none",
        owner="test_user",
        path="/test/file.txt",
        size_bytes=1024,
        last_modified="2025-01-01T00:00:00Z",
        file_type="text/plain",
        is_archive=False,
    )
    normalized = NormalizedInput(entities=entities, context=context)

    result = client.score_from_adapters([normalized])

    assert isinstance(result, ScoringResult), "Should return ScoringResult"
    assert result.score > 0, "Score should be positive"
    assert result.exposure == "INTERNAL", "Should use context exposure"
    print(f"  Score: {result.score}, Tier: {result.tier.value}")
    print(f"  Exposure: {result.exposure}")
    print("  PASSED\n")


def test_score_from_adapters_merge():
    """Test merging multiple adapter outputs."""
    print("Test 8: score_from_adapters with multiple inputs (merge)")
    client = Client()

    # First input - low count, low confidence
    entities1 = [
        Entity(type="SSN", count=1, confidence=0.80, source="adapter1"),
    ]
    context1 = NormalizedContext(
        exposure="PRIVATE",
        encryption="none",
        owner="user1",
        path="/file1.txt",
        size_bytes=512,
        last_modified="2025-01-01T00:00:00Z",
        file_type="text/plain",
        is_archive=False,
    )

    # Second input - higher count, higher confidence
    entities2 = [
        Entity(type="SSN", count=3, confidence=0.95, source="adapter2"),
        Entity(type="CREDIT_CARD", count=2, confidence=0.90, source="adapter2"),
    ]
    context2 = NormalizedContext(
        exposure="PUBLIC",  # Higher exposure
        encryption="none",
        owner="user2",
        path="/file2.txt",
        size_bytes=1024,
        last_modified="2025-01-01T00:00:00Z",
        file_type="text/plain",
        is_archive=False,
    )

    input1 = NormalizedInput(entities=entities1, context=context1)
    input2 = NormalizedInput(entities=entities2, context=context2)

    result = client.score_from_adapters([input1, input2])

    assert isinstance(result, ScoringResult), "Should return ScoringResult"
    # Should take max exposure (PUBLIC)
    assert result.exposure == "PUBLIC", f"Should use highest exposure, got {result.exposure}"
    print(f"  Score: {result.score}, Tier: {result.tier.value}")
    print(f"  Exposure: {result.exposure} (merged from PRIVATE + PUBLIC)")
    print("  PASSED\n")


def test_score_from_adapters_empty():
    """Test scoring with no inputs."""
    print("Test 9: score_from_adapters with empty inputs")
    client = Client()

    result = client.score_from_adapters([])

    assert isinstance(result, ScoringResult), "Should return ScoringResult"
    assert result.score == 0, "Score should be 0 with no inputs"
    assert result.tier == RiskTier.MINIMAL, "Tier should be MINIMAL"
    print(f"  Score: {result.score}, Tier: {result.tier.value}")
    print("  PASSED\n")


def test_default_exposure():
    """Test default exposure setting."""
    print("Test 10: Client with custom default exposure")
    client = Client(default_exposure="INTERNAL")

    result = client.score_text("SSN: 123-45-6789")

    # The exposure multiplier should be applied
    assert result.exposure == "INTERNAL", f"Expected INTERNAL, got {result.exposure}"
    print(f"  Score: {result.score}, Exposure: {result.exposure}")
    print("  PASSED\n")


def main():
    """Run all tests."""
    print("=" * 60)
    print("OpenLabels Client API Tests")
    print("=" * 60 + "\n")

    tests = [
        test_score_text_with_ssn,
        test_score_text_with_credit_card,
        test_score_text_empty,
        test_score_text_with_exposure,
        test_score_file,
        test_score_file_not_found,
        test_score_from_adapters,
        test_score_from_adapters_merge,
        test_score_from_adapters_empty,
        test_default_exposure,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  FAILED: {e}\n")
            failed += 1
        except Exception as e:
            print(f"  ERROR: {type(e).__name__}: {e}\n")
            failed += 1

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
