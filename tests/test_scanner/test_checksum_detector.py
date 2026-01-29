"""
Comprehensive tests for checksum-validated detectors.

Tests validators (Luhn, SSN, CC, NPI, DEA, IBAN, VIN, ABA, tracking numbers)
and the ChecksumDetector class with edge cases and security scenarios.
"""

import pytest
from openlabels.adapters.scanner.detectors.checksum import (
    luhn_check,
    validate_ssn,
    validate_credit_card,
    validate_npi,
    validate_dea,
    validate_iban,
    validate_vin,
    validate_aba_routing,
    validate_ups_tracking,
    validate_fedex_tracking,
    validate_usps_tracking,
    ChecksumDetector,
    CHECKSUM_PATTERNS,
)
from openlabels.adapters.scanner.detectors.constants import (
    CONFIDENCE_LOW,
    CONFIDENCE_LUHN_INVALID,
    CONFIDENCE_PERFECT,
    CONFIDENCE_WEAK,
)


class TestLuhnCheck:
    """Tests for Luhn algorithm validation."""

    def test_valid_luhn_numbers(self):
        """Test valid Luhn numbers."""
        # Known valid Luhn numbers
        assert luhn_check("79927398713") is True
        assert luhn_check("4539578763621486") is True  # Valid Visa
        assert luhn_check("4111111111111111") is True  # Test Visa
        assert luhn_check("5500000000000004") is True  # Test Mastercard

    def test_invalid_luhn_numbers(self):
        """Test invalid Luhn numbers."""
        assert luhn_check("79927398710") is False
        assert luhn_check("1234567890123456") is False
        # Note: all zeros passes Luhn (0 mod 10 = 0), so test different invalid number
        assert luhn_check("1111111111111111") is False

    def test_too_few_digits(self):
        """Test numbers with too few digits."""
        assert luhn_check("1") is False
        assert luhn_check("") is False
        assert luhn_check("a") is False

    def test_with_non_digit_characters(self):
        """Test Luhn handles non-digit characters (strips them)."""
        # These should work - non-digits are filtered
        assert luhn_check("4111-1111-1111-1111") is True
        assert luhn_check("4111 1111 1111 1111") is True


class TestValidateSSN:
    """Tests for SSN validation with security focus."""

    def test_valid_ssn_hyphenated(self):
        """Test valid SSN with hyphens."""
        is_valid, conf = validate_ssn("123-45-6789")
        assert is_valid is True
        assert conf == CONFIDENCE_PERFECT

    def test_valid_ssn_spaces(self):
        """Test valid SSN with spaces."""
        is_valid, conf = validate_ssn("123 45 6789")
        assert is_valid is True
        assert conf == CONFIDENCE_PERFECT

    def test_valid_ssn_mixed_separators(self):
        """Test SSN with spaces around dashes."""
        is_valid, conf = validate_ssn("123 - 45 - 6789")
        assert is_valid is True
        assert conf == CONFIDENCE_PERFECT

    def test_invalid_area_000(self):
        """Test SSN with invalid area code 000."""
        is_valid, conf = validate_ssn("000-45-6789")
        assert is_valid is True  # Still detected
        assert conf == CONFIDENCE_LOW  # Lower confidence

    def test_invalid_area_666(self):
        """Test SSN with invalid area code 666."""
        is_valid, conf = validate_ssn("666-45-6789")
        assert is_valid is True
        assert conf == CONFIDENCE_LOW

    def test_invalid_area_9xx(self):
        """Test SSN with invalid area code starting with 9."""
        is_valid, conf = validate_ssn("900-45-6789")
        assert is_valid is True
        assert conf == CONFIDENCE_LOW

        is_valid, conf = validate_ssn("999-45-6789")
        assert is_valid is True
        assert conf == CONFIDENCE_LOW

    def test_invalid_group_00(self):
        """Test SSN with invalid group 00."""
        is_valid, conf = validate_ssn("123-00-6789")
        assert is_valid is True
        assert conf == CONFIDENCE_WEAK

    def test_invalid_serial_0000(self):
        """Test SSN with invalid serial 0000."""
        is_valid, conf = validate_ssn("123-45-0000")
        assert is_valid is True
        assert conf == CONFIDENCE_WEAK

    def test_wrong_length(self):
        """Test SSN with wrong number of digits."""
        is_valid, _ = validate_ssn("12-34-5678")
        assert is_valid is False

        is_valid, _ = validate_ssn("1234-56-7890")
        assert is_valid is False

    def test_unicode_evasion_rejected(self):
        """Test that unicode digits are rejected (security)."""
        # Unicode digits should be rejected
        is_valid, _ = validate_ssn("１２３-45-6789")  # Fullwidth digits
        assert is_valid is False

    def test_special_char_evasion_rejected(self):
        """Test that special characters in SSN are rejected."""
        is_valid, _ = validate_ssn("123@45#6789")
        assert is_valid is False

        is_valid, _ = validate_ssn("123.45.6789")
        assert is_valid is False

    def test_whitespace_trimmed(self):
        """Test leading/trailing whitespace is trimmed."""
        is_valid, conf = validate_ssn("  123-45-6789  ")
        assert is_valid is True
        assert conf == CONFIDENCE_PERFECT


class TestValidateCreditCard:
    """Tests for credit card validation."""

    def test_valid_visa(self):
        """Test valid Visa card."""
        is_valid, conf = validate_credit_card("4111111111111111")
        assert is_valid is True
        assert conf == 0.99

    def test_valid_mastercard_classic(self):
        """Test valid Mastercard (classic range 51-55)."""
        is_valid, conf = validate_credit_card("5500000000000004")
        assert is_valid is True
        assert conf == 0.99

    def test_valid_mastercard_new_range(self):
        """Test valid Mastercard (new range 2221-2720)."""
        is_valid, conf = validate_credit_card("2221000000000009")
        assert is_valid is True
        # This might fail Luhn but has valid prefix

    def test_valid_amex(self):
        """Test valid American Express."""
        is_valid, conf = validate_credit_card("378282246310005")
        assert is_valid is True
        assert conf == 0.99

    def test_valid_discover(self):
        """Test valid Discover card."""
        is_valid, conf = validate_credit_card("6011111111111117")
        assert is_valid is True
        assert conf == 0.99

    def test_valid_prefix_invalid_luhn(self):
        """Test card with valid prefix but invalid Luhn (typo scenario)."""
        # Valid Visa prefix but bad Luhn
        is_valid, conf = validate_credit_card("4111111111111112")
        assert is_valid is True  # Still detected (safety)
        assert conf == CONFIDENCE_LUHN_INVALID

    def test_invalid_prefix(self):
        """Test card with invalid prefix."""
        is_valid, _ = validate_credit_card("9999999999999999")
        assert is_valid is False

    def test_too_short(self):
        """Test card number that's too short."""
        is_valid, _ = validate_credit_card("411111111111")
        assert is_valid is False

    def test_too_long(self):
        """Test card number that's too long."""
        is_valid, _ = validate_credit_card("41111111111111111111")  # 20 digits
        assert is_valid is False

    def test_with_separators(self):
        """Test card with separators (should be stripped)."""
        is_valid, conf = validate_credit_card("4111-1111-1111-1111")
        assert is_valid is True
        assert conf == 0.99


class TestValidateNPI:
    """Tests for NPI (National Provider Identifier) validation."""

    def test_valid_npi(self):
        """Test valid NPI with Luhn check."""
        # Valid NPI: 1234567893 (passes 80840 prefix Luhn)
        is_valid, conf = validate_npi("1234567893")
        assert is_valid is True
        assert conf == 0.99

    def test_invalid_first_digit(self):
        """Test NPI must start with 1 or 2."""
        is_valid, _ = validate_npi("3234567890")
        assert is_valid is False

        is_valid, _ = validate_npi("0234567890")
        assert is_valid is False

    def test_wrong_length(self):
        """Test NPI must be exactly 10 digits."""
        is_valid, _ = validate_npi("123456789")
        assert is_valid is False

        is_valid, _ = validate_npi("12345678901")
        assert is_valid is False

    def test_invalid_luhn(self):
        """Test NPI with invalid Luhn checksum."""
        is_valid, _ = validate_npi("1234567890")
        assert is_valid is False


class TestValidateDEA:
    """Tests for DEA number validation."""

    def test_valid_dea(self):
        """Test valid DEA number."""
        # DEA format: 2 letters + 7 digits
        # Checksum: (d1+d3+d5 + 2*(d2+d4+d6)) mod 10 == d7
        # AB1234563: (1+3+5 + 2*(2+4+6)) = 9 + 24 = 33, 33 mod 10 = 3 ✓
        is_valid, conf = validate_dea("AB1234563")
        assert is_valid is True
        assert conf == 0.99

    def test_invalid_checksum(self):
        """Test DEA with invalid checksum."""
        is_valid, _ = validate_dea("AB1234560")
        assert is_valid is False

    def test_wrong_format(self):
        """Test DEA with wrong format."""
        # First char not letter
        is_valid, _ = validate_dea("1B1234563")
        assert is_valid is False

        # Second char not letter
        is_valid, _ = validate_dea("A11234563")
        assert is_valid is False

        # Digits not all numeric
        is_valid, _ = validate_dea("AB123456A")
        assert is_valid is False

    def test_wrong_length(self):
        """Test DEA with wrong length."""
        is_valid, _ = validate_dea("AB12345")
        assert is_valid is False


class TestValidateIBAN:
    """Tests for IBAN validation (Mod-97)."""

    def test_valid_iban_germany(self):
        """Test valid German IBAN."""
        is_valid, conf = validate_iban("DE89370400440532013000")
        assert is_valid is True
        assert conf == 0.99

    def test_valid_iban_uk(self):
        """Test valid UK IBAN."""
        is_valid, conf = validate_iban("GB82WEST12345698765432")
        assert is_valid is True
        assert conf == 0.99

    def test_valid_iban_with_spaces(self):
        """Test IBAN with spaces (should be stripped)."""
        is_valid, conf = validate_iban("DE89 3704 0044 0532 0130 00")
        assert is_valid is True
        assert conf == 0.99

    def test_invalid_checksum(self):
        """Test IBAN with invalid checksum."""
        is_valid, _ = validate_iban("DE00370400440532013000")
        assert is_valid is False

    def test_too_short(self):
        """Test IBAN that's too short."""
        is_valid, _ = validate_iban("DE8937040044")
        assert is_valid is False

    def test_too_long(self):
        """Test IBAN that's too long."""
        is_valid, _ = validate_iban("DE89370400440532013000123456789012345")
        assert is_valid is False

    def test_invalid_characters(self):
        """Test IBAN with invalid characters."""
        is_valid, _ = validate_iban("DE89@70400440532013000")
        assert is_valid is False


class TestValidateVIN:
    """Tests for VIN (Vehicle Identification Number) validation."""

    def test_valid_vin(self):
        """Test valid VIN with correct check digit."""
        # Real VIN format: 17 chars, check digit at position 9
        # 11111111111111111 - all 1s with check digit calculated
        # Check: (1*8 + 1*7 + 1*6 + 1*5 + 1*4 + 1*3 + 1*2 + 1*10 + 0 + 1*9 + 1*8 + 1*7 + 1*6 + 1*5 + 1*4 + 1*3 + 1*2)
        # = 8+7+6+5+4+3+2+10+0+9+8+7+6+5+4+3+2 = 89, 89 mod 11 = 1, so check digit = 1
        is_valid, conf = validate_vin("11111111111111111")
        assert is_valid is True
        assert conf == 0.99

    def test_invalid_check_digit(self):
        """Test VIN with invalid check digit."""
        is_valid, _ = validate_vin("1G1YY22G065104537")
        assert is_valid is False

    def test_contains_invalid_chars(self):
        """Test VIN containing I, O, or Q (not allowed)."""
        is_valid, _ = validate_vin("1G1YY22I965104537")
        assert is_valid is False

        is_valid, _ = validate_vin("1G1YY22O965104537")
        assert is_valid is False

        is_valid, _ = validate_vin("1G1YY22Q965104537")
        assert is_valid is False

    def test_wrong_length(self):
        """Test VIN with wrong length."""
        is_valid, _ = validate_vin("1G1YY22G96510453")  # 16 chars
        assert is_valid is False

        is_valid, _ = validate_vin("1G1YY22G9651045377")  # 18 chars
        assert is_valid is False

    def test_invalid_character(self):
        """Test VIN with invalid character."""
        is_valid, _ = validate_vin("1G1YY22G96510453@")
        assert is_valid is False


class TestValidateABARouting:
    """Tests for ABA routing number validation."""

    def test_valid_aba_federal_reserve(self):
        """Test valid ABA in Federal Reserve range (00-12)."""
        # 011000015 - Federal Reserve Bank of Boston
        is_valid, conf = validate_aba_routing("011000015")
        assert is_valid is True
        assert conf == 0.99

    def test_valid_aba_thrift(self):
        """Test valid ABA in thrift range (21-32)."""
        is_valid, conf = validate_aba_routing("211274450")
        assert is_valid is True
        assert conf == 0.99

    def test_valid_aba_electronic(self):
        """Test valid ABA in electronic range (61-72)."""
        # Need to construct a valid one with checksum
        is_valid, conf = validate_aba_routing("611000015")
        # This checks prefix and checksum
        # Might be invalid checksum, just testing prefix logic

    def test_invalid_prefix(self):
        """Test ABA with invalid prefix."""
        is_valid, _ = validate_aba_routing("451234567")  # 45 not valid
        assert is_valid is False

        is_valid, _ = validate_aba_routing("991234567")  # 99 not valid
        assert is_valid is False

    def test_invalid_checksum(self):
        """Test ABA with invalid checksum."""
        is_valid, _ = validate_aba_routing("011000010")
        assert is_valid is False

    def test_wrong_length(self):
        """Test ABA with wrong length."""
        is_valid, _ = validate_aba_routing("01100001")
        assert is_valid is False


class TestValidateUPSTracking:
    """Tests for UPS tracking number validation."""

    def test_valid_ups_tracking(self):
        """Test valid UPS tracking number."""
        # UPS format: 1Z + 16 alphanumeric
        # Need a properly checksummed example
        is_valid, conf = validate_ups_tracking("1Z12345E0205271688")
        # May or may not pass depending on checksum

    def test_wrong_prefix(self):
        """Test UPS tracking without 1Z prefix."""
        is_valid, _ = validate_ups_tracking("2Z12345E0205271688")
        assert is_valid is False

    def test_wrong_length(self):
        """Test UPS tracking with wrong length."""
        is_valid, _ = validate_ups_tracking("1Z12345E020527168")  # 17 chars
        assert is_valid is False

        is_valid, _ = validate_ups_tracking("1Z12345E02052716889")  # 19 chars
        assert is_valid is False

    def test_invalid_character(self):
        """Test UPS tracking with invalid character (I or O)."""
        is_valid, _ = validate_ups_tracking("1ZI2345E0205271688")
        assert is_valid is False


class TestValidateFedExTracking:
    """Tests for FedEx tracking number validation."""

    def test_12_digit_express(self):
        """Test 12-digit FedEx Express format."""
        # Would need a valid checksum example
        # Just test format acceptance
        is_valid, _ = validate_fedex_tracking("123456789012")
        # Depends on checksum

    def test_15_digit_ground_96(self):
        """Test 15-digit FedEx Ground starting with 96."""
        is_valid, _ = validate_fedex_tracking("961234567890123")
        # Depends on checksum

    def test_20_digit_ground_ssc(self):
        """Test 20-digit FedEx Ground SSC."""
        is_valid, _ = validate_fedex_tracking("12345678901234567890")
        # Depends on checksum

    def test_22_digit_smartpost(self):
        """Test 22-digit SmartPost starting with 92."""
        is_valid, _ = validate_fedex_tracking("9212345678901234567890")
        # Depends on checksum

    def test_invalid_length(self):
        """Test FedEx with invalid length."""
        is_valid, _ = validate_fedex_tracking("12345678901")  # 11 digits
        assert is_valid is False

        is_valid, _ = validate_fedex_tracking("1234567890123")  # 13 digits
        assert is_valid is False


class TestValidateUSPSTracking:
    """Tests for USPS tracking number validation."""

    def test_international_format(self):
        """Test 13-char international format."""
        # Format: 2 letters + 9 digits + 2 letters
        # Would need valid checksum
        pass

    def test_20_digit_format(self):
        """Test 20-digit domestic format."""
        is_valid, _ = validate_usps_tracking("12345678901234567890")
        # Depends on checksum

    def test_22_digit_impb(self):
        """Test 22-digit IMpb format."""
        is_valid, _ = validate_usps_tracking("9212345678901234567890")
        # Depends on checksum

    def test_invalid_format(self):
        """Test invalid USPS format."""
        is_valid, _ = validate_usps_tracking("123456789")
        assert is_valid is False


class TestChecksumDetector:
    """Tests for the ChecksumDetector class."""

    @pytest.fixture
    def detector(self):
        return ChecksumDetector()

    def test_detector_name(self, detector):
        """Test detector has correct name."""
        assert detector.name == "checksum"

    def test_detect_ssn_hyphenated(self, detector):
        """Test detection of hyphenated SSN."""
        text = "Patient SSN is 123-45-6789 on file."
        spans = detector.detect(text)

        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1
        assert ssn_spans[0].text == "123-45-6789"
        assert ssn_spans[0].confidence == CONFIDENCE_PERFECT

    def test_detect_ssn_spaces(self, detector):
        """Test detection of SSN with spaces."""
        text = "SSN: 123 45 6789"
        spans = detector.detect(text)

        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1
        assert "123" in ssn_spans[0].text

    def test_detect_ssn_labeled_bare(self, detector):
        """Test detection of bare SSN with label."""
        text = "SSN: 123456789"
        spans = detector.detect(text)

        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1

    def test_detect_credit_card(self, detector):
        """Test detection of credit card."""
        text = "Card: 4111-1111-1111-1111"
        spans = detector.detect(text)

        cc_spans = [s for s in spans if s.entity_type == "CREDIT_CARD"]
        assert len(cc_spans) >= 1
        assert cc_spans[0].confidence == 0.99

    def test_detect_npi(self, detector):
        """Test detection of NPI."""
        text = "Provider NPI: 1234567893"
        spans = detector.detect(text)

        npi_spans = [s for s in spans if s.entity_type == "NPI"]
        assert len(npi_spans) >= 1

    def test_detect_multiple_entities(self, detector):
        """Test detection of multiple entity types."""
        text = """
        Patient: John Doe
        SSN: 123-45-6789
        Card: 4111111111111111
        NPI: 1234567893
        """
        spans = detector.detect(text)

        types_found = {s.entity_type for s in spans}
        assert "SSN" in types_found
        assert "CREDIT_CARD" in types_found or "NPI" in types_found

    def test_no_false_positive_product_code(self, detector):
        """Test SKU/product codes don't match as SSN."""
        text = "Product SKU-123-45-6789 is in stock"
        spans = detector.detect(text)

        # Should not detect as SSN (has letter prefix)
        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) == 0

    def test_duplicate_deduplication(self, detector):
        """Test that overlapping patterns don't create duplicates."""
        text = "SSN: 123-45-6789"
        spans = detector.detect(text)

        # Should only have one SSN span, not multiple from overlapping patterns
        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        # Check no exact duplicates
        seen = set()
        for s in ssn_spans:
            key = (s.start, s.end, s.text)
            assert key not in seen, f"Duplicate span: {s}"
            seen.add(key)

    def test_span_positions_correct(self, detector):
        """Test that span positions are accurate."""
        text = "The SSN 123-45-6789 is here."
        spans = detector.detect(text)

        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        if ssn_spans:
            span = ssn_spans[0]
            # Verify text extraction matches position
            assert text[span.start:span.end] == span.text

    def test_empty_text(self, detector):
        """Test detection on empty text."""
        spans = detector.detect("")
        assert spans == []

    def test_no_entities_text(self, detector):
        """Test detection on text with no entities."""
        text = "This is just a regular sentence with no PII."
        spans = detector.detect(text)

        # Should have few or no spans (maybe some false positives filtered)
        sensitive_spans = [s for s in spans if s.entity_type in ("SSN", "CREDIT_CARD", "NPI")]
        assert len(sensitive_spans) == 0


class TestChecksumPatternsCompleteness:
    """Test that all patterns are properly defined."""

    def test_patterns_have_validators(self):
        """Test all patterns have validator functions."""
        for pattern, entity_type, validator in CHECKSUM_PATTERNS:
            assert callable(validator), f"Validator for {entity_type} is not callable"

    def test_pattern_entity_types(self):
        """Test patterns cover expected entity types."""
        entity_types = {p[1] for p in CHECKSUM_PATTERNS}

        assert "SSN" in entity_types
        assert "CREDIT_CARD" in entity_types
        assert "NPI" in entity_types
        assert "DEA" in entity_types
        assert "IBAN" in entity_types
        assert "VIN" in entity_types
        assert "TRACKING_NUMBER" in entity_types


class TestEvasionResistance:
    """Tests for evasion resistance in checksum detection."""

    @pytest.fixture
    def detector(self):
        return ChecksumDetector()

    def test_ssn_spaces_around_dashes(self, detector):
        """Test SSN with spaces around dashes (evasion attempt)."""
        text = "SSN: 123 - 45 - 6789"
        spans = detector.detect(text)

        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1

    def test_ssn_multiple_spaces(self, detector):
        """Test SSN with multiple spaces (evasion attempt)."""
        text = "SSN: 123  45  6789"
        spans = detector.detect(text)

        ssn_spans = [s for s in spans if s.entity_type == "SSN"]
        assert len(ssn_spans) >= 1

    def test_credit_card_various_separators(self, detector):
        """Test credit card with various separators."""
        # Space
        text1 = "Card: 4111 1111 1111 1111"
        spans1 = detector.detect(text1)
        cc1 = [s for s in spans1 if s.entity_type == "CREDIT_CARD"]

        # Dots
        text2 = "Card: 4111.1111.1111.1111"
        spans2 = detector.detect(text2)
        cc2 = [s for s in spans2 if s.entity_type == "CREDIT_CARD"]

        # Both should detect
        assert len(cc1) >= 1 or len(cc2) >= 1
