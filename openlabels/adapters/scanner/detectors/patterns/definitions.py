"""Pattern definitions for PHI/PII entity recognition."""

import re
from typing import List, Tuple

# PATTERN DEFINITIONS

# Each pattern is (regex, entity_type, confidence, group_index)
# group_index is which capture group contains the value (default 0 = whole match)

PATTERNS: List[Tuple[re.Pattern, str, float, int]] = []


def add_pattern(pattern: str, entity_type: str, confidence: float, group: int = 0, flags: int = 0):
    """Helper to add patterns."""
    PATTERNS.append((re.compile(pattern, flags), entity_type, confidence, group))


# === Phone Numbers ===
add_pattern(r'\((\d{3})\)\s*(\d{3})[-.]?(\d{4})', 'PHONE', 0.90)
add_pattern(r'\b(\d{3})[-.](\d{3})[-.](\d{4})\b', 'PHONE', 0.85)
# International formats - no leading \b since + isn't a word character
add_pattern(r'(?:^|(?<=\s))\+1[-.\s]?(\d{3})[-.\s]?(\d{3})[-.\s]?(\d{4})\b', 'PHONE', 0.90)
add_pattern(r'(?:^|(?<=\s))\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b', 'PHONE', 0.85)
# Labeled phone - tighter pattern: only digits, spaces, dashes, parens, plus
add_pattern(r'(?:phone|tel|fax|call|contact)[:\s]+([()\d\s+.-]{10,20})', 'PHONE', 0.92, 1, re.I)

# === OCR-Aware Phone Patterns ===
# Common OCR substitutions in phone numbers: l/I→1, O→0, S→5, B→8
# Only labeled to reduce false positives
# Phone with S for 5: "(S55) 123-4567" or "55S-1234"
add_pattern(r'(?:phone|tel|call|contact)[:\s]+\(([S5]\d{2})\)\s*(\d{3})[-.]?(\d{4})', 'PHONE', 0.88, 0, re.I)
add_pattern(r'(?:phone|tel|call|contact)[:\s]+\((\d[S5]\d)\)\s*(\d{3})[-.]?(\d{4})', 'PHONE', 0.88, 0, re.I)
add_pattern(r'(?:phone|tel|call|contact)[:\s]+\((\d{2}[S5])\)\s*(\d{3})[-.]?(\d{4})', 'PHONE', 0.88, 0, re.I)
# Phone with l/I for 1: "(555) l23-4567"
add_pattern(r'(?:phone|tel|call|contact)[:\s]+\((\d{3})\)\s*([lI1]\d{2})[-.]?(\d{4})', 'PHONE', 0.88, 0, re.I)
# Phone with B for 8: "(555) 123-456B" or "55B-1234"
add_pattern(r'(?:phone|tel|call|contact)[:\s]+\((\d{3})\)\s*(\d{3})[-.]?(\d{3}[B8])', 'PHONE', 0.88, 0, re.I)

# === Email ===
add_pattern(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'EMAIL', 0.95)
add_pattern(r'(?:email|e-mail)[:\s]+([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})', 'EMAIL', 0.96, 1, re.I)

# === Dates ===
add_pattern(r'\b(\d{1,2})/(\d{1,2})/(\d{4})\b', 'DATE', 0.70)
add_pattern(r'\b(\d{1,2})-(\d{1,2})-(\d{4})\b', 'DATE', 0.70)
add_pattern(r'\b(\d{4})-(\d{1,2})-(\d{1,2})\b', 'DATE', 0.70)
# Dates with 2-digit years: "12/27/25", "01/15/24"
# Lower confidence due to ambiguity (could be scores, prices, etc.)
add_pattern(r'\b(\d{1,2}/\d{1,2}/\d{2})\b', 'DATE', 0.65)
add_pattern(r'\b(\d{1,2}-\d{1,2}-\d{2})\b', 'DATE', 0.65)

# Date with dots (European format): "15.03.1985" or "03.15.1985"
add_pattern(r'(?:DOB|Date)[:\s]+(\d{1,2}\.\d{1,2}\.\d{4})', 'DATE', 0.85, 1, re.I)
add_pattern(r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b', 'DATE', 0.75, 0, re.I)
add_pattern(r'\b\d{1,2}\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\b', 'DATE', 0.75, 0, re.I)
# Edge case: "November 3., 1986" - day with period before comma/year (evasion pattern)
add_pattern(r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}\.,\s*\d{4}\b', 'DATE', 0.78, 0, re.I)
# Abbreviated month names: "Oct 11, 1984", "Mar 19, 1988", "Jan 15th, 1980"
add_pattern(r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}\b', 'DATE', 0.75, 0, re.I)
add_pattern(r'\b\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+\d{4}\b', 'DATE', 0.75, 0, re.I)
# DOB with abbreviated months
add_pattern(r'(?:DOB|Date\s+of\s+Birth|Birth\s*date)[:\s]+((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\.?\s+\d{1,2},?\s+\d{4})', 'DATE_DOB', 0.95, 1, re.I)
add_pattern(r'(?:DOB|Date\s+of\s+Birth|Birth\s*date)[:\s]+(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})', 'DATE_DOB', 0.95, 1, re.I)
add_pattern(r'(?:admission|admit|discharge)[:\s]+(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})', 'DATE', 0.90, 1, re.I)

# === Ordinal Date Formats ===
# "3rd of March, 1990", "1st of January, 2020"
add_pattern(r'\b(\d{1,2}(?:st|nd|rd|th)\s+of\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)(?:\s*,?\s*\d{4})?)\b', 'DATE', 0.80, 0, re.I)
# "3rd of March" (without year), "22nd of December"
add_pattern(r'\b(\d{1,2}(?:st|nd|rd|th)\s+of\s+(?:January|February|March|April|May|June|July|August|September|October|November|December))\b', 'DATE', 0.75, 0, re.I)
# "3rd March 1990", "1st January 2020" (ordinal without "of")
add_pattern(r'\b(\d{1,2}(?:st|nd|rd|th)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)(?:\s*,?\s*\d{4})?)\b', 'DATE', 0.78, 0, re.I)
# "the 15th of January" (with "the")
add_pattern(r'\b(the\s+\d{1,2}(?:st|nd|rd|th)\s+of\s+(?:January|February|March|April|May|June|July|August|September|October|November|December))\b', 'DATE', 0.80, 0, re.I)

# === Weekday + Date Formats ===
# "Fri, Mar 3, 2024", "Monday, January 15, 2024"
add_pattern(r'\b((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\s*,?\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec|January|February|March|April|May|June|July|August|September|October|November|December)\.?\s+\d{1,2}\s*,?\s*\d{4})\b', 'DATE', 0.82, 0, re.I)

# === Date ranges with written months ===
# "between January 1 and January 15"
add_pattern(r'\b((?:between|from)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2})\b', 'DATE', 0.75, 0, re.I)
add_pattern(r'\b((?:and|to|through)\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2})\b', 'DATE', 0.75, 0, re.I)
# "March 1-15, 2024" (date range with hyphen)
add_pattern(r'\b((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2}\s*[-–—]\s*\d{1,2}\s*,?\s*\d{4})\b', 'DATE', 0.78, 0, re.I)

# === Time ===
# Safe Harbor requires removal of time elements (they're part of date under HIPAA)
# Standard 12-hour: "11:30 PM", "9:42 AM", "11:30PM"
add_pattern(r'\b(\d{1,2}:\d{2}\s*(?:AM|PM|am|pm|a\.m\.|p\.m\.))\b', 'TIME', 0.88, 0, re.I)
# With seconds: "11:30:45 PM"
add_pattern(r'\b(\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM|am|pm|a\.m\.|p\.m\.))\b', 'TIME', 0.88, 0, re.I)
# Contextual: "at 3:30 PM", "@ 11:45"
add_pattern(r'(?:at|@)\s*(\d{1,2}:\d{2}\s*(?:AM|PM|am|pm)?)\b', 'TIME', 0.85, 1, re.I)
# Labeled: "Time: 14:30", "recorded at 2:15 PM"
add_pattern(r'(?:time|recorded|documented|signed)[:\s]+(\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM|am|pm)?)', 'TIME', 0.90, 1, re.I)

# === 24-hour time formats ===
# "14:30:00" - 24-hour with seconds (ISO style)
add_pattern(r'\b(\d{2}:\d{2}:\d{2})\b', 'TIME', 0.82, 1)

# === ISO 8601 datetime formats ===
# "2024-03-15T14:30:00Z" - full ISO with timezone
add_pattern(r'\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b', 'DATETIME', 0.92, 1)
# "2024-03-15 14:30:00" - ISO-like without T separator  
add_pattern(r'\b(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\b', 'DATETIME', 0.88, 1)

# === Timezone-aware times ===
# "14:30:00-05:00" - time with timezone offset
add_pattern(r'\b(\d{2}:\d{2}:\d{2}[+-]\d{2}:?\d{2})\b', 'TIME', 0.85, 1)
# "14:30:00Z" - time with Z (UTC) suffix
add_pattern(r'\b(\d{2}:\d{2}:\d{2}Z)\b', 'TIME', 0.88, 1)

# === Clinical time contexts ===
# "Surgery began 08:00", "procedure at 14:30"
add_pattern(r'(?:began|started|ended|completed|performed)\s+(?:at\s+)?(\d{2}:\d{2})\b', 'TIME', 0.85, 1, re.I)

# === Age ===
# Standard forms: "46 years old", "46 year old"
add_pattern(r'\b(\d{1,3})\s*(?:year|yr)s?\s*old\b', 'AGE', 0.90, 1, re.I)
# Hyphenated form: "46-year-old" (common in clinical notes)
add_pattern(r'\b(\d{1,3})[-‐‑–—]\s*(?:year|yr)s?[-‐‑–—]\s*old\b', 'AGE', 0.90, 1, re.I)
# Abbreviations: "46 y/o", "46y/o", "46 yo", "46yo"
add_pattern(r'\b(\d{1,3})\s*y/?o\b', 'AGE', 0.88, 1, re.I)
# Labeled: "age 46", "aged 46"
add_pattern(r'\b(?:age|aged)[:\s]+(\d{1,3})\b', 'AGE', 0.92, 1, re.I)  # \b prevents matching "Page 123"

# === Room/Bed Numbers (facility location identifiers) ===
# "Room: 625", "Rm: 302A", "Room 101"
add_pattern(r'(?:Room|Rm)[:\s#]+(\d{1,4}[A-Z]?)', 'ROOM', 0.88, 1, re.I)
# "Bed: 2", "Bed 3A"
add_pattern(r'(?:Bed)[:\s#]+(\d{1,2}[A-Z]?)', 'ROOM', 0.85, 1, re.I)
# Combined: "Room 302, Bed 2"
add_pattern(r'(?:Room|Rm)[:\s#]+(\d{1,4}[A-Z]?)\s*,?\s*(?:Bed)[:\s#]*(\d{1,2}[A-Z]?)', 'ROOM', 0.90, 0, re.I)


# NAME PATTERNS

# === Name Components ===
# Name part: MUST start with capital letter (proper noun)
# Unicode: include common accented characters (José, François)
# FIXED: Support Irish/Scottish names like O'Connor, O'Brien, McDonald, MacArthur
# Pattern: Capital + lowercase + optional (apostrophe/hyphen + Capital + lowercase)
_NAME = r"[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ''-]*(?:[''-][A-ZÀ-ÖØ-Þa-zà-öø-ÿ][a-zà-öø-ÿ]*)?"

# Multi-part names: handles "Mary Anne", "Jean-Pierre", "van der Berg"
_NAME_PART = r"(?:[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ''-]*(?:[''-][A-ZÀ-ÖØ-Þa-zà-öø-ÿ][a-zà-öø-ÿ]*)?)"

# Use [ \t]+ (horizontal whitespace) NOT \s+ (which includes newlines)

# === Initials patterns (J. Wilson, A. Smith, R.J. Thompson) ===
# Single initial: "J. Wilson" or "J Wilson" (with optional period)
_INITIAL = r"[A-Z]\.?"
# Double initial: "R.J." or "R. J." or "RJ"
_DOUBLE_INITIAL = r"[A-Z]\.?\s*[A-Z]\.?"

# === Credential Suffixes (comprehensive list) ===
# Medical doctors, nurses, physician assistants, pharmacists, therapists, dentists, etc.
_CREDENTIALS = (
    r'(?:MD|DO|MBBS|'                           # Medical doctors
    r'RN|BSN|MSN|LPN|LVN|CNA|'                  # Nurses
    r'NP|FNP|ANP|PNP|ACNP|AGNP|WHNP|'          # Nurse practitioners
    r'DNP|APRN|CNM|CNS|CRNA|'                   # Advanced practice nurses
    r'PA|PA-C|'                                  # Physician assistants
    r'PhD|PharmD|RPh|'                          # Pharmacists/researchers
    r'DPM|DPT|OT|OTR|PT|'                       # Podiatry, therapy
    r'DDS|DMD|RDH|'                             # Dentistry
    r'OD|'                                       # Optometry
    r'DC|'                                       # Chiropractic
    r'LCSW|LMFT|LPC|LMHC|PsyD|'                 # Mental health (licensed)
    r'MSW|LMSW|LSW|LISW|DSW|CSW|'              # Social work credentials
    r'RT|RRT|CRT|'                              # Respiratory therapy
    r'EMT|EMT-P|Paramedic|'                     # Emergency medical
    r'MA|CMA|RMA|CCMA)'                         # Medical assistants
)

# === PROVIDER PATTERNS WITH TITLE AND CREDENTIALS ===
# These patterns capture the FULL span including Dr./Doctor prefix and credential suffixes

# Single-word provider name with Dr.: "Dr. Ali", "Dr. Singh" (common in consult notes)
# NOTE: No re.I - _NAME must stay case-sensitive to avoid matching "from", "the", etc.
add_pattern(rf'((?:[Dd][Rr]\.?|[Dd]octor)[ \t]+{_NAME})\b', 'NAME_PROVIDER', 0.88, 1)

# Dr./Doctor + First Last: "Dr. John Smith", "Doctor Jane Doe"
# NOTE: No re.I - _NAME must stay case-sensitive to avoid matching lowercase words
add_pattern(rf'((?:[Dd][Rr]\.?|[Dd]octor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{1,2}})\b', 'NAME_PROVIDER', 0.94, 1)

# Dr./Doctor + Initial + Last: "Dr. J. Smith", "Dr. R.J. Thompson"
add_pattern(rf'((?:Dr\.?|Doctor)[ \t]+{_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', 0.90, 1, re.I)
add_pattern(rf'((?:Dr\.?|Doctor)[ \t]+{_DOUBLE_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', 0.90, 1, re.I)

# Name + Credentials (no Dr.): "John Smith, MD", "Jane Doe, RN", "S. Roberts, DNP"
# NOTE: No re.I flag - credentials must be uppercase to avoid matching "slept" as PT, "edema" as MA
# NOTE: \b at start prevents matching mid-word like "repORT" -> "O RT"
add_pattern(rf'\b({_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})\b', 'NAME_PROVIDER', 0.92, 1)
add_pattern(rf'\b({_INITIAL}[ \t]+{_NAME},?\s*{_CREDENTIALS})\b', 'NAME_PROVIDER', 0.90, 1)
add_pattern(rf'\b({_DOUBLE_INITIAL}[ \t]+{_NAME},?\s*{_CREDENTIALS})\b', 'NAME_PROVIDER', 0.90, 1)

# Dr. + Name + Credentials: "Dr. John Smith, MD" (redundant but occurs)
# NOTE: re.I kept for "Dr./Doctor" but credentials must match case
add_pattern(rf'((?:Dr\.?|Doctor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})\b', 'NAME_PROVIDER', 0.95, 1)

# Electronic signature context (high confidence): "Electronically signed by: Joyce Kim, RN"
add_pattern(rf'(?:Electronically\s+signed|E-signed|Authenticated|Verified|Approved)\s+(?:by)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})', 'NAME_PROVIDER', 0.96, 1, re.I)
add_pattern(rf'(?:Electronically\s+signed|E-signed|Authenticated|Verified|Approved)\s+(?:by)[:\s]+((?:Dr\.?|Doctor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PROVIDER', 0.96, 1, re.I)

# Lab/clinical context: "drawn by J. Wilson" "reviewed by A. Smith MD"
add_pattern(rf'(?:drawn|reviewed|verified|reported|signed|approved|dictated|transcribed|entered|ordered)\s+(?:by|per)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})', 'NAME_PROVIDER', 0.88, 1, re.I)
add_pattern(rf'(?:drawn|reviewed|verified|reported|signed|approved|dictated|transcribed|entered|ordered)\s+(?:by|per)[:\s]+({_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', 0.72, 1)
add_pattern(rf'(?:drawn|reviewed|verified|reported|signed|approved|dictated|transcribed|entered|ordered)\s+(?:by|per)[:\s]+({_DOUBLE_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', 0.72, 1)

# cc: list context: "cc: Dr. M. Brown, Cardiology"
add_pattern(rf'(?:cc|CC)[:\s]+((?:Dr\.?|Doctor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PROVIDER', 0.85, 1, re.I)
add_pattern(rf'(?:cc|CC)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}},?\s*{_CREDENTIALS})', 'NAME_PROVIDER', 0.85, 1, re.I)

# Nurse/NP/PA with name: "Nurse Jane Smith", "NP John Doe"
# NOTE: \b prevents matching "Return" as "RN", colon required to prevent cross-line matching
add_pattern(rf'\b(?:Nurse|NP|PA|RN):\s*({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PROVIDER', 0.85, 1, re.I)

# Provider with label - IMPORTANT: Middle initial requires period
_MIDDLE_INITIAL = r"[A-Z]\."

# Primary patterns - First Last, First Middle Last
add_pattern(rf'(?:Provider|Attending|Referring|Ordering|Treating|Primary\s+Care|Consultant)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{1,2}})', 'NAME_PROVIDER', 0.94, 1, re.I)
add_pattern(rf'(?:Provider|Attending|Referring|Ordering|Treating|Primary\s+Care|Consultant)[:\s]+((?:Dr\.?|Doctor)[ \t]+{_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PROVIDER', 0.95, 1, re.I)
# With middle initial (period required): "Provider: Jonathan K. Kim"
add_pattern(rf'(?:Provider|Attending|Referring|Ordering|Treating|Primary\s+Care)[:\s]+({_NAME}[ \t]+{_MIDDLE_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', 0.94, 1)
# Signature patterns
add_pattern(rf'(?:Provider\s+Signature)[:\s]*({_NAME}(?:[ \t]+{_NAME}){{1,2}})', 'NAME_PROVIDER', 0.94, 1, re.I)
add_pattern(rf'(?:Provider\s+Signature)[:\s]*({_NAME}[ \t]+{_MIDDLE_INITIAL}[ \t]+{_NAME})', 'NAME_PROVIDER', 0.94, 1)

# School/social services staff patterns (counselors, social workers, etc.)
# These appear in pediatric notes and school records
add_pattern(rf'(?:School\s+)?(?:Counselor|Social\s*Worker|Psychologist|Principal|Teacher)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{1,2}},?\s*{_CREDENTIALS})', 'NAME', 0.94, 1, re.I)
add_pattern(rf'(?:School\s+)?(?:Counselor|Social\s*Worker|Psychologist|Principal|Teacher)[:\s]+({_NAME}[ \t]+{_MIDDLE_INITIAL}[ \t]+{_NAME})', 'NAME', 0.92, 1, re.I)
add_pattern(rf'(?:School\s+)?(?:Counselor|Social\s*Worker|Psychologist|Principal|Teacher)[:\s]+({_NAME}[ \t]+{_MIDDLE_INITIAL}[ \t]+{_NAME},?\s*{_CREDENTIALS})', 'NAME', 0.94, 1, re.I)

# Handwritten/cursive signature detection (common on IDs)
# Matches names that appear with mixed case in signature style (e.g., "Andrew Sample")
# This catches signatures that OCR extracts from ID cards
add_pattern(rf'\b([A-Z][a-z]+\s+[A-Z][a-z]+)\s*$', 'NAME', 0.75, 1)  # First Last at end of line

# ID card signature after restrictions field (e.g., "RESTR:NONE Andrew Sample 5DD:")
# On driver's licenses, signature appears after the restrictions field
add_pattern(r'(?:RESTR|RESTRICTION)[:\s]*(?:NONE|[A-Z])\s+([A-Z][a-z]+\s+[A-Z][a-z]+)(?=\s+\d|\s*$)', 'NAME', 0.85, 1, re.I)

# === ID CARD ALL-CAPS NAME PATTERNS ===
# Driver's licenses and state IDs often have names in ALL CAPS
# These patterns use positional/contextual clues to avoid false positives

# Last name after DOB on ID cards: "DOB: 01/01/1990 SMITH 2 JOHN"
# Field code 1 = last name, but may not have "1" prefix in OCR
add_pattern(r'(?:DOB)[:\s]+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\s+([A-Z]{2,20})(?=\s+\d|\s*$)', 'NAME', 0.82, 1, re.I)

# First/middle name after field code 2: "2 JOHN MICHAEL 8" or "2 ANDREW JASON 8123"
# Must be followed by field code 8 (address) which starts with digit
add_pattern(r'\b2\s+([A-Z]{2,15}(?:\s+[A-Z]{2,15})?)\s+(?=\d{1,5}\s+[A-Z])', 'NAME', 0.80, 1)

# === INTERNATIONAL LABELED NAME PATTERNS ===
# French: Nom, Prénom (last name, first name)
add_pattern(rf'(?:Nom|Prénom|Nom\s+de\s+famille)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1, re.I)
# German: Name, Vorname, Nachname (name, first name, last name)
add_pattern(rf'(?:Vorname|Nachname|Familienname)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1, re.I)
# Spanish: Nombre, Apellido (name, surname)
add_pattern(rf'(?:Nombre|Apellido|Apellidos)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1, re.I)
# Italian: Nome, Cognome (name, surname)
add_pattern(rf'(?:Nome|Cognome)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1, re.I)
# Dutch: Naam, Voornaam, Achternaam (name, first name, last name)
add_pattern(rf'(?:Naam|Voornaam|Achternaam)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1, re.I)
# Portuguese: Nome, Sobrenome (name, surname)
add_pattern(rf'(?:Sobrenome)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1, re.I)
# Full name field (international): "Full Name:", "Complete Name:"
add_pattern(rf'(?:Full\s+Name|Complete\s+Name|Legal\s+Name|Vollständiger\s+Name|Nom\s+complet|Nombre\s+completo)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{1,3}})', 'NAME', 0.90, 1, re.I)

# === PATIENT NAME PATTERNS ===

# Patient labeled patterns - REQUIRE COLON to avoid matching "Patient reports..."
add_pattern(rf'(?:Patient(?:\s+Name)?|Pt):\s*({_NAME}(?:[ \t]+{_NAME}){{1,3}})', 'NAME_PATIENT', 0.92, 1, re.I)

# Patient without colon - REQUIRES First Last format (two+ capitalized words) to avoid false positives
# "Patient John Smith" matches, but "Patient reports" doesn't (lowercase verb)
# IMPORTANT: NO re.I flag - name parts must be Capitalized to distinguish from verbs
# Using (?i:Patient) for case-insensitive prefix only
add_pattern(rf'\b(?i:Patient)[ \t]+({_NAME}[ \t]+{_NAME}(?:[ \t]+{_NAME})?)\b', 'NAME_PATIENT', 0.87, 1)
add_pattern(rf'(?:Name):\s*({_NAME}(?:[ \t]+{_NAME}){{1,3}})', 'NAME_PATIENT', 0.88, 1, re.I)
add_pattern(rf'(?:RE|Re|Regarding):\s*({_NAME}(?:[ \t]+{_NAME}){{1,3}})\s*\(', 'NAME_PATIENT', 0.90, 1, re.I)
# Last, First format common in referrals: "RE: Smith, John" - capture as "Smith, John"
add_pattern(rf'(?:RE|Re|Regarding):\s*({_NAME},\s*{_NAME}(?:[ \t]+{_NAME}){{0,1}})', 'NAME_PATIENT', 0.90, 1, re.I)

# Single labeled name: "Patient: John" - requires explicit colon
add_pattern(rf'(?:Patient):\s*({_NAME})\b', 'NAME_PATIENT', 0.75, 1, re.I)

# Patient names with initials: "Patient: A. Whitaker", "Patient: A. B. Smith"
add_pattern(rf'(?:Patient(?:\s+Name)?|Pt):\s*({_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', 0.90, 1, re.I)
add_pattern(rf'(?:Patient(?:\s+Name)?|Pt):\s*({_DOUBLE_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', 0.90, 1, re.I)
# Patient names with middle initial: "Patient: John A. Smith"
add_pattern(rf'(?:Patient(?:\s+Name)?|Pt):\s*({_NAME}[ \t]+{_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', 0.92, 1, re.I)

# Last, First format without RE: prefix (common in headers/lists)
# "Smith, John" - only when followed by context like DOB, MRN, or newline
add_pattern(rf'({_NAME}),\s+({_NAME})(?=\s*(?:\(|DOB|MRN|SSN|\d{{1,2}}/|\n))', 'NAME_PATIENT', 0.72, 0)

# Last, First in prescription/order context: "prescribed to Smith, John"
add_pattern(rf'(?:prescribed|ordered|given|administered|dispensed)\s+(?:to|for)\s+({_NAME},\s+{_NAME})', 'NAME_PATIENT', 0.75, 1, re.I)

# Inline names: "the patient, John Smith, arrived" - comma-delimited name
add_pattern(rf'(?:(?:the)\s+)?(?:patient),\s+({_NAME}(?:[ \t]+{_NAME}){{1,2}}),', 'NAME_PATIENT', 0.78, 1, re.I)

# Patient patterns - Mr/Mrs/Ms/Miss indicate patient (non-provider) in clinical context
# NOTE: \b required to prevent "symptoms" matching as "Ms" + name
add_pattern(rf'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PATIENT', 0.90, 1, re.I)

# === INTERNATIONAL HONORIFIC/TITLE PATTERNS ===
# German: Herr, Frau, Fräulein
add_pattern(rf'\b(?:Herr|Frau|Fräulein|Hr\.|Fr\.)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1)
# French: Monsieur, Madame, Mademoiselle, Docteur(e)
add_pattern(rf'\b(?:Monsieur|Madame|Mademoiselle|M\.|Mme\.?|Mlle\.?|Docteur|Docteure|Dr\.)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1)
# Spanish: Señor, Señora, Señorita, Don, Doña
add_pattern(rf'\b(?:Señor|Señora|Señorita|Sr\.|Sra\.|Srta\.|Don|Doña)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1)
# Italian: Signor, Signora, Signorina
add_pattern(rf'\b(?:Signor|Signora|Signorina|Sig\.|Sig\.ra|Sig\.na)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1)
# Dutch: Meneer, Mevrouw, de heer, mevrouw (often followed by name)
add_pattern(rf'\b(?:Meneer|Mevrouw|Mevr\.|Dhr\.|de[ \t]+heer)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1)
# Portuguese: Senhor, Senhora
add_pattern(rf'\b(?:Senhor|Senhora|Sr\.|Sra\.)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME', 0.88, 1)
# With initials: "Mr. A. Whitaker", "Mrs. A. B. Smith"
add_pattern(rf'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss)[ \t]+({_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', 0.90, 1, re.I)
add_pattern(rf'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss)[ \t]+({_DOUBLE_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', 0.90, 1, re.I)
# With middle initial: "Mr. John A. Smith"
add_pattern(rf'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss)[ \t]+({_NAME}[ \t]+{_INITIAL}[ \t]+{_NAME})', 'NAME_PATIENT', 0.92, 1, re.I)

# === RELATIVE/FAMILY NAME PATTERNS ===

# Explicit labels
add_pattern(rf'(?:Emergency\s+Contact|Next\s+of\s+Kin|NOK)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,3}})', 'NAME_RELATIVE', 0.88, 1, re.I)
add_pattern(rf'(?:Spouse|Partner|Guardian|Caregiver)[:\s]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_RELATIVE', 0.88, 1, re.I)

# Relationship context: "husband John", "wife Mary", "son Michael"
# NOTE: \b required to prevent "Anderson" matching as "son", [ \t]+ prevents newline crossing
add_pattern(rf'\b(?:husband|wife|spouse|partner|son|daughter|mother|father|brother|sister|parent|child|guardian)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_RELATIVE', 0.82, 1, re.I)
# Possessive: "patient's husband John", "her mother Mary"
add_pattern(rf'\b(?:patient\'?s?|his|her|their)[ \t]+(?:husband|wife|spouse|partner|son|daughter|mother|father|brother|sister|parent|child)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_RELATIVE', 0.85, 1, re.I)
# "mother's name is Sarah", "father is John Smith"
add_pattern(rf'\b(?:mother|father|spouse|partner|guardian)(?:\'s[ \t]+name)?[ \t]+(?:is|was)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_RELATIVE', 0.80, 1, re.I)

# === SELF-IDENTIFICATION PATTERNS ===
# "my name is John Smith", "I am John Smith", "I'm John Smith"
# High confidence because explicit self-identification is very clear
add_pattern(rf'\b(?:my\s+name\s+is|I\s+am|I\'m)[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})', 'NAME_PATIENT', 0.90, 1, re.I)
# "this is John Smith" (phone/intro context)
add_pattern(rf'\bthis\s+is[ \t]+({_NAME}(?:[ \t]+{_NAME}){{0,2}})(?:\s+speaking|\s+calling)?', 'NAME_PATIENT', 0.85, 1, re.I)


# === STANDALONE NAME PATTERNS (CLINICAL CONTEXT) ===
# These patterns detect single first names in clinical/conversational contexts
# where ML models may fail. Case-sensitive _NAME prevents matching verbs.
# NOTE: NO re.I flag - _NAME must stay case-sensitive to avoid matching lowercase words.
# Use (?i:...) inline for case-insensitive verb matching only.

# Clinical verb + name: "saw John", "examined Mary", "treated Bob"
# Wide range of clinical verbs that precede patient names
# NOTE: Single name only (no {1,2}) - multi-word names handled by other patterns
_CLINICAL_VERBS_PAST = (
    r'(?i:saw|examined|evaluated|assessed|treated|diagnosed|'
    r'admitted|discharged|transferred|referred|counseled|advised|'
    r'informed|educated|instructed|observed|monitored|'
    r'interviewed|consulted|cleared|stabilized|sedated|intubated)'
)
add_pattern(rf'\b{_CLINICAL_VERBS_PAST}[ \t]+({_NAME})\b', 'NAME_PATIENT', 0.82, 1)

# "spoke with John", "met with Mary", "talked to Bob"
add_pattern(rf'\b(?i:spoke|met|talked|visited|checked|followed\s+up)[ \t]+(?i:with|to)[ \t]+({_NAME})\b', 'NAME_PATIENT', 0.80, 1)

# Name's + clinical term (possessive): "John's condition", "Mary's symptoms"
_CLINICAL_NOUNS = (
    r'(?i:condition|symptoms?|diagnosis|prognosis|labs?|results?|'
    r'medication|medications|treatment|therapy|care|recovery|'
    r'vitals?|imaging|x-?rays?|scans?|tests?|bloodwork|'
    r'chart|records?|history|case|progress|status|'
    r'appointment|visit|admission|discharge|surgery|procedure|'
    r'prescription|dosage|regimen|pain|complaints?|'
    r'family|wife|husband|mother|father|son|daughter|'
    r'doctor|physician|nurse|provider|specialist)'
)
add_pattern(rf"\b({_NAME})'s[ \t]+{_CLINICAL_NOUNS}\b", 'NAME_PATIENT', 0.82, 1)

# NOTE: Removed aggressive standalone name patterns to improve precision:
# - "Name + verb" patterns (John said, Mary has)
# - Greeting/closing patterns (Hi John, Thanks Mary)
# - Direct address patterns (John, please...)
# - Transport patterns (bring John to)
# These caused too many false positives. Keep only labeled/contextual patterns.

# MEDICAL IDENTIFIERS

# === Medical Record Numbers ===
add_pattern(r'(?:MRN|Medical\s+Record(?:\s+Number)?)[:\s#]+([A-Z]*-?\d{6,12}[A-Z]*)', 'MRN', 0.95, 1, re.I)
add_pattern(r'\b(MRN-\d{6,12})\b', 'MRN', 0.92, 1, re.I)  # Bare MRN-1234567 format
add_pattern(r'(?:patient\s+ID|patient\s*#|pt\s+ID)[:\s#]+([A-Z]*-?\d{6,12}[A-Z]*)', 'MRN', 0.88, 1, re.I)  # "patient ID" variant
add_pattern(r'(?:Encounter|Visit)[:\s#]+([A-Z]*\d{6,12}[A-Z]*)', 'ENCOUNTER_ID', 0.90, 1, re.I)
add_pattern(r'(?:Accession|Lab)[:\s#]+([A-Z]*\d{6,12}[A-Z]*)', 'ACCESSION_ID', 0.90, 1, re.I)

# === NPI (National Provider Identifier) ===
# NPI is a 10-digit number with Luhn checksum (same algorithm as credit cards)
# Labeled: "NPI: 1234567890", "NPI# 1234567890"
add_pattern(r'(?:NPI)[:\s#]+(\d{10})\b', 'NPI', 0.95, 1, re.I)
# Contextual: "provider NPI 1234567890"
add_pattern(r'(?:provider|physician|prescriber|ordering)\s+NPI[:\s#]*(\d{10})\b', 'NPI', 0.92, 1, re.I)
# DEA number (provider controlled substance license): 2 letters + 7 digits
add_pattern(r'(?:DEA)[:\s#]+([A-Z]{2}\d{7})\b', 'DEA', 0.95, 1, re.I)

# === Health Plan IDs ===
add_pattern(r'(?:Member\s*ID|Subscriber)[:\s#]+([A-Z0-9]{6,15})', 'MEMBER_ID', 0.88, 1, re.I)
add_pattern(r'(?:Medicaid)[:\s#]+([A-Z0-9]{8,12})', 'HEALTH_PLAN_ID', 0.88, 1, re.I)

# === Medicare Beneficiary Identifier (MBI) - CMS format since 2020 ===
# Format: 11 chars = C-AN-N-L-AN-N-L-AN-N-AN with optional dashes
# Pos 1: 1-9 (not 0), Pos 2,5,8: Letters (not S,L,O,I,B,Z)
# Pos 3,6,9,11: Alphanumeric (not S,L,O,I,B,Z), Pos 4,7,10: Digits
_MBI_LETTER = r'[ACDEFGHJKMNPQRTUVWXY]'
_MBI_ALNUM = r'[ACDEFGHJKMNPQRTUVWXY0-9]'
_MBI_PATTERN = rf'[1-9]{_MBI_LETTER}{_MBI_ALNUM}\d-?{_MBI_LETTER}{_MBI_ALNUM}\d-?{_MBI_LETTER}{_MBI_ALNUM}\d{_MBI_ALNUM}'

# Labeled MBI patterns (high confidence)
add_pattern(rf'(?:Medicare\s*(?:Beneficiary\s*)?(?:ID|#|Number)?|MBI)[:\s#()]*({_MBI_PATTERN})', 'MEDICARE_ID', 0.97, 1, re.I)
add_pattern(rf'(?:Beneficiary\s*ID)[:\s#]*({_MBI_PATTERN})', 'MEDICARE_ID', 0.95, 1, re.I)
# After other Medicare labels like "Medicare ID (MBI):"
add_pattern(rf'(?:ID\s*\(MBI\))[:\s#]*({_MBI_PATTERN})', 'MEDICARE_ID', 0.96, 1, re.I)
# Bare MBI pattern (moderate confidence - distinct format unlikely to be random)
add_pattern(rf'\b({_MBI_PATTERN})\b', 'MEDICARE_ID', 0.82, 1)
add_pattern(r'(?:RXBIN|RX\s*BIN)[:\s]+(\d{6})', 'PHARMACY_ID', 0.90, 1, re.I)
add_pattern(r'(?:RXPCN|RX\s*PCN)[:\s]+([A-Z0-9]{4,10})', 'PHARMACY_ID', 0.88, 1, re.I)
add_pattern(r'(?:Group(?:\s*(?:Number|No|#))?)[:\s#]+([A-Z0-9-]{4,15})', 'HEALTH_PLAN_ID', 0.75, 1, re.I)

# Member ID with letter prefix and hyphen (e.g., BC-993812, BVH-882391)
add_pattern(r'(?:Member\s*ID)[:\s#]+([A-Z]{2,4}-\d{5,12})', 'MEMBER_ID', 0.92, 1, re.I)
# Bare insurance ID format: 2-4 letters, hyphen, 5-12 digits (contextual)
add_pattern(r'\b([A-Z]{2,4}-\d{5,12})\b', 'HEALTH_PLAN_ID', 0.70, 1)

# Payer-prefixed member IDs (e.g., BCBS-987654321, UHC123456789)
_PAYER_PREFIXES = (
    r'BCBS|BlueCross|BlueShield|'
    r'UHC|UnitedHealth(?:care)?|'
    r'Aetna|Cigna|Humana|Kaiser|'
    r'Anthem|Centene|Molina|HCSC|'
    r'Tricare|TRICARE|Medicaid|Medicare|'
    r'Ambetter|Amerigroup|WellCare|'
    r'Oscar|Clover|Devoted|'
    r'Caremark|OptumRx|Express\s*Scripts'
)
# Require at least one digit in the ID portion to avoid matching company names
add_pattern(rf'(?:{_PAYER_PREFIXES})[- ]?([A-Z]*\d[A-Z0-9]{{5,14}})', 'HEALTH_PLAN_ID', 0.90, 1, re.I)
add_pattern(rf'((?:{_PAYER_PREFIXES})[- ]?[A-Z]*\d[A-Z0-9]{{5,14}})', 'HEALTH_PLAN_ID', 0.88, 0, re.I)


# ADDRESS PATTERNS

# === Street Suffixes (shared) ===
_STREET_SUFFIXES = (
    # Common
    r'Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|'
    r'Court|Ct|Way|Place|Pl|'
    # Additional common suffixes
    r'Terrace|Ter|Terr|Circle|Cir|Trail|Trl|Parkway|Pkwy|Pky|'
    r'Highway|Hwy|Square|Sq|Loop|Path|Alley|Aly|'
    r'Crossing|Xing|Point|Pt|Pike|Run|Pass|Cove|'
    r'Glen|Ridge|View|Hill|Heights|Hts|Park|Plaza|Walk|Commons|'
    r'Expressway|Expy|Freeway|Fwy|Turnpike|Tpke|'
    # Residential
    r'Row|Mews|Close|Gardens|Gdn|Estate|Estates'
)

# === State Abbreviations (shared) ===
_STATE_ABBREV = r'(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)'

# === Full State Names (shared) ===
_STATE_FULL = r'(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New\s+Hampshire|New\s+Jersey|New\s+Mexico|New\s+York|North\s+Carolina|North\s+Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode\s+Island|South\s+Carolina|South\s+Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West\s+Virginia|Wisconsin|Wyoming)'

# === City Name Pattern (shared) ===
_CITY_NAME = r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*"  # Capitalized words

# === Multi-line Address (discharge summary format) ===
# Matches:
#   ADDRESS: 123 Main St
#            Springfield, IL 62701
# Captures the FULL address as a single span
add_pattern(
    rf'ADDRESS:\s*'
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'\s*[\n\r]+\s*'  # Newline with leading whitespace on next line
    rf'{_CITY_NAME}\s*,\s*{_STATE_ABBREV}\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', 0.96, 1, re.I
)

# === Multi-line Address WITHOUT label (common in forms/documents) ===
# Matches:
#   2199 Seventh Place
#            San Antonio, TX 78201
# Captures the FULL address as a single span
add_pattern(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'\s*[\n\r]+\s*'  # Newline with leading whitespace on next line
    rf'{_CITY_NAME}\s*,\s*{_STATE_ABBREV}\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', 0.94, 1, re.I
)

# === Full Address Patterns (industry standard - single span) ===
# Full address: street, optional apt, city, state, zip
# "5734 Mill Highway, Apt 773, Springfield, IL 62701"
add_pattern(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'(?:\s*,?\s*(?:Apt|Suite|Ste|Unit|#|Bldg|Building|Floor|Fl)\.?\s*#?\s*[A-Za-z0-9]+)?'
    rf'\s*,\s*{_CITY_NAME}'
    rf'\s*,\s*{_STATE_ABBREV}'
    rf'\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', 0.95, 1, re.I
)

# Full address without apt: "123 Main St, Springfield, IL 62701"
add_pattern(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'\s*,\s*{_CITY_NAME}'
    rf'\s*,\s*{_STATE_ABBREV}'
    rf'\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', 0.94, 1, re.I
)

# Full address without comma before state: "123 Main St, Boston MA 02101"
add_pattern(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'\s*,\s*{_CITY_NAME}'
    rf'\s+{_STATE_ABBREV}'  # No comma, just space before state
    rf'\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', 0.93, 1, re.I
)

# Address without ZIP: "123 Main St, Springfield, IL"
add_pattern(
    rf'(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?'
    rf'(?:\s*,?\s*(?:Apt|Suite|Ste|Unit|#|Bldg|Building|Floor|Fl)\.?\s*#?\s*[A-Za-z0-9]+)?'
    rf'\s*,\s*{_CITY_NAME}'
    rf'\s*,\s*{_STATE_ABBREV})\b',
    'ADDRESS', 0.92, 1, re.I
)

# City, State ZIP: "Springfield, IL 62701"
add_pattern(
    rf'({_CITY_NAME}\s*,\s*{_STATE_ABBREV}\s+\d{{5}}(?:-\d{{4}})?)',
    'ADDRESS', 0.90, 1
)

# City, State without ZIP: "Springfield, IL"
add_pattern(
    rf'({_CITY_NAME}\s*,\s*{_STATE_ABBREV})\b(?!\s*\d)',
    'ADDRESS', 0.85, 1
)

# Street address only (no city/state): "123 Main St" or "5734 Mill Highway, Apt 773"
add_pattern(
    rf'\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES})\.?\b'
    rf'(?:\s*,?\s*(?:Apt|Suite|Ste|Unit|#|Bldg|Building|Floor|Fl)\.?\s*#?\s*[A-Za-z0-9]+)?',
    'ADDRESS', 0.82, 0, re.I
)

# === Directional Street Addresses (no suffix required) ===
# Common format: "9820 W. Fairview", "1050 S. Vista", "4500 NE Industrial"
# The directional prefix strongly indicates address context even without street suffix
_DIRECTIONAL = r'(?:N|S|E|W|NE|NW|SE|SW|North|South|East|West|Northeast|Northwest|Southeast|Southwest)\.?'
add_pattern(
    rf'\b(\d+[A-Za-z]?\s+{_DIRECTIONAL}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b',
    'ADDRESS', 0.88, 1
)

# ID card field-labeled address: "8 123 MAIN STREET" where 8 is field number
# Matches: single digit + space + normal street address
add_pattern(
    rf'\b\d\s+(\d+[A-Za-z]?\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:{_STREET_SUFFIXES}))\.?\b',
    'ADDRESS', 0.90, 1, re.I
)

# All-caps street address (common in OCR from IDs): "123 MAIN STREET"
add_pattern(
    rf'\b(\d+[A-Z]?\s+[A-Z]+(?:\s+[A-Z]+)*\s+(?:STREET|ST|AVENUE|AVE|ROAD|RD|BOULEVARD|BLVD|LANE|LN|DRIVE|DR|COURT|CT|WAY|PLACE|PL|TERRACE|TER|CIRCLE|CIR|TRAIL|TRL|PARKWAY|PKWY|HIGHWAY|HWY))\b',
    'ADDRESS', 0.88, 1
)

# PO Box
add_pattern(r'P\.?O\.?\s*Box\s+\d+', 'ADDRESS', 0.88, 0, re.I)

# Context-based location: "lives in Springfield", "from Chicago"
# NOTE: No re.I flag - _CITY_NAME requires capitalized words to avoid matching
# everything after "from" (e.g., "from Los Angeles treated" would match too much)
add_pattern(rf'(?:[Ll]ives?\s+in|[Ff]rom|[Rr]esident\s+of|[Ll]ocated\s+in|[Bb]ased\s+in|[Bb]orn\s+in)\s+({_CITY_NAME})', 'ADDRESS', 0.80, 1)

# === ZIP Code (standalone, labeled only) ===
add_pattern(r'(?:ZIP|Postal|Zip\s*Code)[:\s]+(\d{5}(?:-\d{4})?)', 'ZIP', 0.95, 1, re.I)

# === HIPAA Safe Harbor Restricted ZIP Prefixes ===
# These 17 prefixes have populations < 20,000 and MUST be detected even without labels
# Per 45 CFR §164.514(b)(2)(i)(B), they get replaced with "000" in safe harbor output
# Ref: scanner pipeline for the transformation logic

# Vermont (036, 059)
add_pattern(r'\b(036\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)
add_pattern(r'\b(059\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)

# Connecticut (063)
add_pattern(r'\b(063\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)

# New York (102)
add_pattern(r'\b(102\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)

# Connecticut (203) - Note: area code overlap, but zip detection context helps
add_pattern(r'\b(203\d{2}(?:-\d{4})?)\b', 'ZIP', 0.85, 1)

# Minnesota (556)
add_pattern(r'\b(556\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)

# Guam/Pacific (692)
add_pattern(r'\b(692\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)

# Texas (790)
add_pattern(r'\b(790\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)

# Wyoming (821, 823, 830, 831)
add_pattern(r'\b(821\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)
add_pattern(r'\b(823\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)
add_pattern(r'\b(830\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)
add_pattern(r'\b(831\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)

# Colorado/Utah (878, 879, 884)
add_pattern(r'\b(878\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)
add_pattern(r'\b(879\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)
add_pattern(r'\b(884\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)

# Nevada (890, 893)
add_pattern(r'\b(890\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)
add_pattern(r'\b(893\d{2}(?:-\d{4})?)\b', 'ZIP', 0.88, 1)

# NOTE: European patterns (streets, postal codes, dates) are in european.py
# They only run on non-English text to avoid false positives.

# FACILITY PATTERNS

_FACILITY_PREFIX = r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}"  # 1-4 capitalized words
add_pattern(rf'({_FACILITY_PREFIX}\s+(?:Hospital|Medical\s+Center|Health\s+Center|Clinic|Health\s+System|Healthcare|Specialty\s+Clinic|Regional\s+Medical))\b', 'FACILITY', 0.85, 1)
add_pattern(rf'({_FACILITY_PREFIX}\s+(?:Memorial|General|Community|University|Regional|Veterans|Children\'s)\s+Hospital)\b', 'FACILITY', 0.88, 1)
add_pattern(rf'({_FACILITY_PREFIX}\s+(?:Group|LLC|Ltd|Inc|Associates|Partners)\s+Hospital)\b', 'FACILITY', 0.85, 1)

# St./Saint prefixed facilities (very common in healthcare)
# High confidence to override any misclassification of "St" as ADDRESS
add_pattern(r"(St\.?\s+[A-Z][a-z]+(?:'s)?\s+(?:Hospital|Medical\s+Center|Health\s+Center|Clinic|Health\s+System|Heart\s+Institute|Cancer\s+Center|Children's\s+Hospital))", 'FACILITY', 0.92, 1)
add_pattern(r"(Saint\s+[A-Z][a-z]+(?:'s)?\s+(?:Hospital|Medical\s+Center|Health\s+Center|Clinic|Health\s+System|Heart\s+Institute|Cancer\s+Center|Children's\s+Hospital))", 'FACILITY', 0.92, 1)
# Generic St./Saint + Name patterns (catch-all for other facility types)
add_pattern(r"(St\.?\s+[A-Z][a-z]+(?:'s)?(?:\s+[A-Z][a-z]+){1,3})\s+(?:Hospital|Center|Clinic|Institute|Foundation)", 'FACILITY', 0.88, 0)
add_pattern(r"(Saint\s+[A-Z][a-z]+(?:'s)?(?:\s+[A-Z][a-z]+){1,3})\s+(?:Hospital|Center|Clinic|Institute|Foundation)", 'FACILITY', 0.88, 0)

# === Specialty Clinics and Medical Practices ===
# Specialty names that appear in clinic/center names
_MEDICAL_SPECIALTY = (
    r'Pulmonary|Cardiology|Cardio|Cardiac|Dermatology|Derma|Gastro(?:enterology)?|'
    r'Neurology|Neuro|Oncology|Orthopedic|Ortho|Pediatric|Psych(?:iatry|ology)?|'
    r'Radiology|Rheumatology|Urology|ENT|Ophthalmology|Optometry|'
    r'Allergy|Immunology|Endocrin(?:e|ology)?|Nephrology|Hematology|'
    r'OB-?GYN|Obstetrics|Gynecology|Family\s+Medicine|Internal\s+Medicine|'
    r'Primary\s+Care|Urgent\s+Care|Sleep|Pain|Spine|Vascular|Wound|'
    r'Physical\s+Therapy|Occupational\s+Therapy|Speech\s+Therapy|Rehabilitation|Rehab'
)
# "[Name] Pulmonary Clinic", "[Name] Cardiology Center"
add_pattern(rf'({_FACILITY_PREFIX}\s+(?:{_MEDICAL_SPECIALTY})\s+(?:Clinic|Center|Associates|Practice|Group|Specialists))\b', 'FACILITY', 0.90, 1, re.I)

# Multi-part specialty facilities with "&": "Pulmonary & Sleep Center", "Cardiology & Vascular Associates"
add_pattern(rf'((?:{_MEDICAL_SPECIALTY})\s+(?:&|and)\s+(?:{_MEDICAL_SPECIALTY})\s+(?:Center|Clinic|Associates|Institute|Specialists))\b', 'FACILITY', 0.92, 1, re.I)

# "[Name] Pulmonary & Sleep Center" (name prefix + specialty combo)
add_pattern(rf'({_FACILITY_PREFIX}\s+(?:{_MEDICAL_SPECIALTY})\s+(?:&|and)\s+(?:{_MEDICAL_SPECIALTY})\s+(?:Center|Clinic|Associates))\b', 'FACILITY', 0.92, 1, re.I)

# Context-labeled facilities: "Clinic:", "Hospital:", "Center:" followed by name
add_pattern(rf'(?:Clinic|Hospital|Center|Practice)[:\s]+({_FACILITY_PREFIX}(?:\s+(?:{_MEDICAL_SPECIALTY}))?(?:\s+(?:&|and)\s+[A-Z][a-z]+)*(?:\s+(?:Center|Clinic|Associates|Practice))?)', 'FACILITY', 0.90, 1, re.I)

# Standalone specialty practice names: "Pulmonary Associates", "Sleep Center", "Pain Specialists"
add_pattern(rf'\b((?:{_MEDICAL_SPECIALTY})\s+(?:Associates|Specialists|Center|Clinic|Practice|Group|Partners))\b', 'FACILITY', 0.85, 1, re.I)

# === PHARMACY CHAINS (PHI when combined with patient data) ===
# Major retail pharmacy chains - include optional store number
_PHARMACY_CHAINS = (
    r'Walgreens|CVS(?:\s+Pharmacy|\s+Health)?|Rite\s*Aid|Walmart\s+Pharmacy|'
    r'Costco\s+Pharmacy|Kroger\s+Pharmacy|Publix\s+Pharmacy|'
    r'Safeway\s+Pharmacy|Albertsons\s+Pharmacy|'
    r'Target\s+Pharmacy|Sam\'s\s+Club\s+Pharmacy|'
    r'Walgreen(?:\'s)?|Wal-?greens|'
    r'Caremark|Express\s+Scripts|OptumRx|Cigna\s+Pharmacy|'
    r'Humana\s+Pharmacy|Kaiser\s+Pharmacy|'
    r'Good\s+Neighbor\s+Pharmacy|Health\s*Mart'
)
# Pharmacy with optional store number (e.g., "Walgreens Pharmacy #10472")
add_pattern(rf'((?:{_PHARMACY_CHAINS})(?:\s+Pharmacy)?(?:\s*#?\d{{3,6}})?)', 'FACILITY', 0.92, 1, re.I)
# "Preferred Pharmacy:" or "Pharmacy:" label followed by pharmacy name
add_pattern(rf'(?:Preferred\s+)?Pharmacy[:\s]+((?:{_PHARMACY_CHAINS})(?:\s+Pharmacy)?(?:\s*#?\d{{3,6}})?)', 'FACILITY', 0.94, 1, re.I)
# Bare pharmacy chain name when it appears alone
add_pattern(rf'\b((?:{_PHARMACY_CHAINS})\s+Pharmacy(?:\s*#\d{{3,6}})?)(?:\s|,|$)', 'FACILITY', 0.90, 1, re.I)

# NETWORK/DEVICE IDENTIFIERS
# === IP Address ===
add_pattern(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', 'IP_ADDRESS', 0.85)
# IPv6 - full or compressed format
add_pattern(r'\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7})\b', 'IP_ADDRESS', 0.85)  # Full
add_pattern(r'\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){2,7})\b', 'IP_ADDRESS', 0.80)  # Compressed

# === MAC Address ===
add_pattern(r'\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', 'MAC_ADDRESS', 0.90)

# === IMEI ===
add_pattern(r'(?:IMEI)[:\s]+(\d{15})', 'IMEI', 0.95, 1, re.I)

# === Device Serial Numbers (medical devices) ===
# Labeled patterns for pacemakers, insulin pumps, hearing aids, etc.
add_pattern(r'(?:Serial(?:\s*(?:Number|No|#))?|S/N|SN)[:\s]+([A-Z0-9]{6,20})', 'DEVICE_ID', 0.90, 1, re.I)
add_pattern(r'(?:Device\s*(?:ID|Identifier|Serial))[:\s]+([A-Z0-9]{6,20})', 'DEVICE_ID', 0.92, 1, re.I)
add_pattern(r'(?:Pacemaker|ICD|Defibrillator|Pump|Implant)\s+(?:ID|Serial|S/N)[:\s]+([A-Z0-9]{6,20})', 'DEVICE_ID', 0.94, 1, re.I)

# === URLs ===
add_pattern(r'https?://[^\s<>"{}|\\^`\[\]]+', 'URL', 0.90)

# === Biometric Identifiers (Safe Harbor #16) ===
add_pattern(r'(?:Fingerprint|Biometric|Retinal?|Iris|Voice(?:print)?|DNA)\s+(?:ID|Sample|Scan|Record|Data)[:\s#]+([A-Z0-9]{6,30})', 'BIOMETRIC_ID', 0.90, 1, re.I)
add_pattern(r'(?:Genetic|Genomic|DNA)\s+(?:Test|Sample|Analysis)\s+(?:ID|#|Number)[:\s]+([A-Z0-9]{6,20})', 'BIOMETRIC_ID', 0.88, 1, re.I)

# === Photographic Image Identifiers (Safe Harbor #17) ===
add_pattern(r'(?:Photo|Image|Picture|Photograph)\s+(?:ID|File|#)[:\s]+([A-Z0-9_-]{6,30})', 'IMAGE_ID', 0.85, 1, re.I)
add_pattern(r'(?:DICOM|Study|Series|Image)\s+(?:UID|ID)[:\s]+([0-9.]{10,64})', 'IMAGE_ID', 0.92, 1, re.I)

# === Username ===
add_pattern(r'(?:username|user|login|userid)[:\s]+([A-Za-z0-9_.-]{3,30})', 'USERNAME', 0.85, 1, re.I)
# International username labels (FR: nom d'utilisateur, DE: Benutzername, ES: usuario, NL: gebruikersnaam, IT: nome utente, PT: usuário)
add_pattern(r'(?:nom d\'utilisateur|benutzername|usuario|gebruikersnaam|nome utente|usuário|utilisateur)[:\s]+([\w._-]{3,30})', 'USERNAME', 0.85, 1, re.I | re.UNICODE)
# NOTE: Removed @ mention and greeting patterns - too many false positives
# Login context: "logged in as username", "signed in as username"
# NOTE: Removed "account" - it matches account numbers, not usernames
add_pattern(r'(?:logged\s+in\s+as|signed\s+in\s+as|profile)[:\s]+([A-Za-z0-9_.-]{3,30})', 'USERNAME', 0.82, 1, re.I)

# === Password ===
# English password labels - require colon/equals separator (not just whitespace) to avoid FPs
add_pattern(r'(?:password|passwd|pwd|passcode|pin)\s*[=:]\s*([^\s]{4,50})', 'PASSWORD', 0.90, 1, re.I)
# International password labels (DE: Kennwort/Passwort, FR: mot de passe, ES: contraseña, IT: password, NL: wachtwoord, PT: senha)
add_pattern(r'(?:kennwort|passwort|mot\s+de\s+passe|contraseña|wachtwoord|senha|parola\s+d\'ordine)[:\s]+([^\s]{4,50})', 'PASSWORD', 0.90, 1, re.I | re.UNICODE)
# Authentication context: "credentials: password", "secret: xxxxx"
add_pattern(r'(?:credential|secret|auth\s+key|api\s+key|access\s+key|secret\s+key)[:\s]+([^\s]{8,100})', 'PASSWORD', 0.88, 1, re.I)
# Temp/initial password context
add_pattern(r'(?:temporary|temp|initial|default)\s+(?:password|pwd|passcode)[:\s]+([^\s]{4,50})', 'PASSWORD', 0.92, 1, re.I)
# LICENSE/CREDENTIAL/GOVERNMENT IDs
# === Driver's License - Labeled ===
add_pattern(r'(?:Driver\'?s?\s*License|DL|DLN)[:\s#]+([A-Z0-9]{5,15})', 'DRIVER_LICENSE', 0.88, 1, re.I)

# === Driver's License - State-specific formats (bare patterns) ===
# These catch DL numbers even without labels, based on known state formats

# --- Florida: Letter + 3-3-2-3-1 with dashes (W426-545-30-761-0) ---
add_pattern(r'\b([A-Z]\d{3}-\d{3}-\d{2}-\d{3}-\d)\b', 'DRIVER_LICENSE', 0.95, 1)
# Florida without dashes (OCR may miss them): W4265453076110
add_pattern(r'\b([A-Z]\d{12}0)\b', 'DRIVER_LICENSE', 0.85, 1)

# --- California: Letter + 7 digits (A1234567) ---
add_pattern(r'\b([A-Z]\d{7})\b', 'DRIVER_LICENSE', 0.72, 1)

# --- New York: 9 digits OR Letter + 7 digits + space + 3 digits ---
# Note: 9 digit overlaps with SSN, so need context
add_pattern(r'(?:DL|License)[:\s]+(\d{9})\b', 'DRIVER_LICENSE', 0.85, 1, re.I)

# --- Pennsylvania: 8 digits ---
add_pattern(r'\b(\d{8})\b(?=.*(?:PA|Pennsylvania|DL|License))', 'DRIVER_LICENSE', 0.75, 1, re.I)

# --- Illinois: Letter + 11-12 digits (A12345678901) ---
add_pattern(r'\b([A-Z]\d{11,12})\b', 'DRIVER_LICENSE', 0.82, 1)

# --- Ohio: 2 letters + 6 digits (AB123456) OR 8 digits ---
add_pattern(r'\b([A-Z]{2}\d{6})\b', 'DRIVER_LICENSE', 0.78, 1)

# --- Michigan: Letter + 10-12 digits ---
add_pattern(r'\b([A-Z]\d{10,12})\b', 'DRIVER_LICENSE', 0.80, 1)

# --- New Jersey: Letter + 14 digits ---
add_pattern(r'\b([A-Z]\d{14})\b', 'DRIVER_LICENSE', 0.85, 1)

# --- Virginia: Letter + 8-9 digits OR 9 digits (with context) ---
add_pattern(r'\b([A-Z]\d{8,9})\b', 'DRIVER_LICENSE', 0.75, 1)

# --- Maryland: Letter + 12 digits ---
# (Covered by Michigan pattern above)

# --- Wisconsin: Letter + 13 digits ---
add_pattern(r'\b([A-Z]\d{13})\b', 'DRIVER_LICENSE', 0.82, 1)

# --- Washington: WDL prefix + alphanumeric (12 chars total like WDL*ABC1234D) ---
add_pattern(r'\b(WDL[A-Z0-9*]{9})\b', 'DRIVER_LICENSE', 0.92, 1)

# --- Hawaii: H + 8 digits (H12345678) ---
add_pattern(r'\b(H\d{8})\b', 'DRIVER_LICENSE', 0.85, 1)

# --- Colorado: 2 letters + 3-6 digits OR 9 digits (with context) ---
add_pattern(r'\b([A-Z]{2}\d{3,6})\b', 'DRIVER_LICENSE', 0.72, 1)
add_pattern(r'(?:CO|Colorado|DL)[:\s]+(\d{9})\b', 'DRIVER_LICENSE', 0.80, 1, re.I)

# --- Nevada: 9-12 digits, often starts with X or 9 ---
add_pattern(r'\b(X\d{8,11})\b', 'DRIVER_LICENSE', 0.85, 1)
add_pattern(r'(?:NV|Nevada|DL)[:\s]+(\d{9,12})\b', 'DRIVER_LICENSE', 0.78, 1, re.I)

# --- New Hampshire: 2 digits + 3 letters + 5 digits (12ABC34567) ---
add_pattern(r'\b(\d{2}[A-Z]{3}\d{5})\b', 'DRIVER_LICENSE', 0.88, 1)

# --- North Dakota: 3 letters + 6 digits (ABC123456) ---
add_pattern(r'\b([A-Z]{3}\d{6})\b', 'DRIVER_LICENSE', 0.82, 1)

# --- Iowa: 3 digits + 2 letters + 4 digits (123AB4567) OR 9 digits ---
add_pattern(r'\b(\d{3}[A-Z]{2}\d{4})\b', 'DRIVER_LICENSE', 0.88, 1)

# --- Kansas: K + 8 digits (K12345678) ---
add_pattern(r'\b(K\d{8})\b', 'DRIVER_LICENSE', 0.85, 1)

# --- Massachusetts: S + 8 digits (S12345678) ---
add_pattern(r'\b(S\d{8})\b', 'DRIVER_LICENSE', 0.85, 1)

# --- Arizona: Letter + 8 digits OR 9 digits with context ---
add_pattern(r'(?:AZ|Arizona|DL)[:\s]+([A-Z]?\d{8,9})\b', 'DRIVER_LICENSE', 0.80, 1, re.I)

# --- Minnesota: Letter + 12 digits ---
# (Covered by Illinois pattern: Letter + 11-12 digits)

# --- Kentucky: Letter + 8-9 digits ---
# (Covered by Virginia pattern: Letter + 8-9 digits)

# --- Louisiana: 8 digits, often starts with 00 ---
add_pattern(r'\b(00\d{6})\b', 'DRIVER_LICENSE', 0.80, 1)

# --- Indiana: 4 digits + 2 letters + 4 digits (1234AB5678) OR 10 digits ---
add_pattern(r'\b(\d{4}[A-Z]{2}\d{4})\b', 'DRIVER_LICENSE', 0.88, 1)
add_pattern(r'(?:IN|Indiana|DL)[:\s]+(\d{10})\b', 'DRIVER_LICENSE', 0.78, 1, re.I)

# --- Oregon: 1-7 digits OR Letter + 6 digits ---
add_pattern(r'\b([A-Z]\d{6})\b', 'DRIVER_LICENSE', 0.72, 1)

# --- Connecticut: 9 digits (with context, overlaps SSN) ---
add_pattern(r'(?:CT|Connecticut|DL)[:\s]+(\d{9})\b', 'DRIVER_LICENSE', 0.78, 1, re.I)

# --- Texas: 8 digits (with context) ---
add_pattern(r'(?:TX|Texas|DL)[:\s]+(\d{8})\b', 'DRIVER_LICENSE', 0.78, 1, re.I)

# --- Georgia: 7-9 digits (with context) ---
add_pattern(r'(?:GA|Georgia|DL)[:\s]+(\d{7,9})\b', 'DRIVER_LICENSE', 0.78, 1, re.I)

# --- Alabama: 7 digits (with context) ---
add_pattern(r'(?:AL|Alabama|DL)[:\s]+(\d{7})\b', 'DRIVER_LICENSE', 0.78, 1, re.I)

# --- Missouri: Letter + 5-10 digits OR 9 digits with context ---
add_pattern(r'(?:MO|Missouri|DL)[:\s]+([A-Z]?\d{5,10})\b', 'DRIVER_LICENSE', 0.78, 1, re.I)

# --- Tennessee: 7-9 digits (with context) ---
add_pattern(r'(?:TN|Tennessee|DL)[:\s]+(\d{7,9})\b', 'DRIVER_LICENSE', 0.78, 1, re.I)

# --- South Carolina: 5-11 digits (with context) ---
add_pattern(r'(?:SC|South\s+Carolina|DL)[:\s]+(\d{5,11})\b', 'DRIVER_LICENSE', 0.78, 1, re.I)

# --- General formats ---
# Letter(s) + 5-14 digits (many states)
add_pattern(r'\b([A-Z]{1,2}\d{5,14})\b', 'DRIVER_LICENSE', 0.68, 1)

# DL with spaces (like "99 999999" from PA sample)
add_pattern(r'(?:DL|DLN)[:\s#]+(\d{2}\s+\d{6})', 'DRIVER_LICENSE', 0.90, 1, re.I)

# DL with dashes - generic (captures FL and others)
add_pattern(r'(?:DL|DLN)[:\s#]+([A-Z]?\d{2,4}[-\s]\d{2,4}[-\s]\d{2,4}[-\s]?\d{0,4})', 'DRIVER_LICENSE', 0.92, 1, re.I)

# === State ID (non-driver) ===
add_pattern(r'(?:State\s*ID|ID\s*Card)[:\s#]+([A-Z0-9]{5,15})', 'STATE_ID', 0.88, 1, re.I)

# === ID Card trailing numbers (document discriminator, inventory numbers) ===
# These appear after "ORGAN DONOR", "DD:", or at end of ID card text
add_pattern(r'(?:ORGAN\s*DONOR|VETERAN)\s+(\d{10,15})\s*$', 'UNIQUE_ID', 0.85, 1, re.I)
# Document discriminator without DD label (often at end of ID)
add_pattern(r'(?:DD[:\s]+\d{10,15}\s+)(\d{10,15})\s*$', 'UNIQUE_ID', 0.80, 1)

# === Passport ===
add_pattern(r'(?:Passport)[:\s#]+([A-Z0-9]{6,12})', 'PASSPORT', 0.88, 1, re.I)
# US passport format: 9 digits or alphanumeric
add_pattern(r'\b([A-Z]?\d{8,9})\b(?=.*[Pp]assport)', 'PASSPORT', 0.75, 1)

# === Medical License ===
add_pattern(r'(?:Medical\s+License|License\s+#)[:\s]+([A-Z0-9]{5,15})', 'MEDICAL_LICENSE', 0.88, 1, re.I)

# === Military IDs ===
# EDIPI (Electronic Data Interchange Personal Identifier) - 10 digits
add_pattern(r'(?:EDIPI|DoD\s*ID|Military\s*ID)[:\s#]+(\d{10})\b', 'MILITARY_ID', 0.92, 1, re.I)
# FAX NUMBERS (explicit patterns - often caught by PHONE but good to be specific)
add_pattern(r'(?:fax|facsimile)[:\s]+([()\d\s+.-]{10,20})', 'FAX', 0.92, 1, re.I)
add_pattern(r'(?:f|fax)[:\s]*\((\d{3})\)\s*(\d{3})[-.]?(\d{4})', 'FAX', 0.90)
add_pattern(r'(?:f|fax)[:\s]*(\d{3})[-.](\d{3})[-.](\d{4})', 'FAX', 0.88)
# PRESCRIPTION / RX NUMBERS
add_pattern(r'(?:Rx|Rx\s*#|Prescription|Script)[:\s#]+(\d{6,12})', 'RX_NUMBER', 0.88, 1, re.I)
add_pattern(r'(?:Rx|Prescription)\s+(?:Number|No|#)[:\s]+([A-Z0-9]{6,15})', 'RX_NUMBER', 0.90, 1, re.I)
add_pattern(r'(?:Refill|Fill)\s+#[:\s]*(\d{1,3})\s+of\s+(\d{1,3})', 'RX_NUMBER', 0.75, 0, re.I)  # "Refill #2 of 5"


# FINANCIAL IDENTIFIERS

# === SSN (labeled) - higher confidence than unlabeled ===
add_pattern(r'(?:SSN|Social\s*Security(?:\s*(?:Number|No|#))?)[:\s#]+(\d{3}[-\s]?\d{2}[-\s]?\d{4})', 'SSN', 0.96, 1, re.I)
add_pattern(r'(?:last\s*4|last\s*four)[:\s]+(\d{4})\b', 'SSN_PARTIAL', 0.80, 1, re.I)
# Bare 9-digit - LOW confidence (0.70) so labeled MRN/Account patterns (0.95) win
add_pattern(r'\b((?!000|666|9\d\d)\d{9})\b', 'SSN', 0.70)

# SSN with unusual separators (dots, middle dots, spaces around hyphens)
add_pattern(r'(?:SSN|Social\s*Security)[:\s#]+(\d{3}[.\xb7]\d{2}[.\xb7]\d{4})', 'SSN', 0.85, 1, re.I)  # dots/middle dots
add_pattern(r'(?:SSN|Social\s*Security)[:\s#]+(\d{3}\s*-\s*\d{2}\s*-\s*\d{4})', 'SSN', 0.88, 1, re.I)  # spaces around hyphens

# === ABA Routing (labeled only) ===
add_pattern(r'(?:Routing|ABA|RTN)[:\s#]+(\d{9})\b', 'ABA_ROUTING', 0.95, 1, re.I)
# Account numbers - both numeric-only and alphanumeric formats
add_pattern(r'(?:Account)\s*(?:Number|No|#)?[:\s#]+(\d{8,17})\b', 'ACCOUNT_NUMBER', 0.88, 1, re.I)
add_pattern(r'(?:Account)\s*(?:Number|No|#)?[:\s#]+([A-Z0-9][-A-Z0-9]{5,19})', 'ACCOUNT_NUMBER', 0.85, 1, re.I)

# === Certificate/License Numbers (Safe Harbor #11) ===
add_pattern(r'(?:Certificate|Certification)\s+(?:Number|No|#)[:\s]+([A-Z0-9-]{5,20})', 'CERTIFICATE_NUMBER', 0.85, 1, re.I)
# NOTE: Require at least one digit to avoid matching "Radiologist"
add_pattern(r'(?:Board\s+Certified?|Certified)\s+#?[:\s]*([A-Z]*\d[A-Z0-9]{4,14})', 'CERTIFICATE_NUMBER', 0.80, 1, re.I)

# === Additional Account Numbers (Safe Harbor #10) ===
add_pattern(r'(?:Patient\s+)?(?:Acct)\s*(?:Number|No|#)?[:\s#]+([A-Z0-9-]{6,20})', 'ACCOUNT_NUMBER', 0.85, 1, re.I)
add_pattern(r'(?:Invoice|Billing|Statement)\s*(?:Number|No|#)?\s*[:#]\s*([A-Z0-9-]{6,20})', 'ACCOUNT_NUMBER', 0.80, 1, re.I)
add_pattern(r'(?:Claim)\s*(?:Number|No|#)?\s*[:#]\s*([A-Z0-9-]{8,20})', 'CLAIM_NUMBER', 0.88, 1, re.I)

# === Unique Identifiers (Safe Harbor #18) - Catch-all ===
# Require explicit colon or # separator (not just whitespace) to avoid FPs
add_pattern(r'(?:Case|File|Record)\s*(?:Number|No|#)?\s*[:#]\s*([A-Z0-9-]{5,20})', 'UNIQUE_ID', 0.75, 1, re.I)

# === Credit Card Numbers ===
# 13-19 digits, optionally separated by spaces/dashes
# Luhn validation done in detector
add_pattern(r'(?:Card|Credit\s*Card|CC|Payment)[:\s#]+(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7})', 'CREDIT_CARD', 0.94, 1, re.I)
# Bare credit card patterns (with separators to distinguish from random numbers)
add_pattern(r'\b(\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4})\b', 'CREDIT_CARD', 0.88, 1)
add_pattern(r'\b(\d{4}[\s-]\d{6}[\s-]\d{5})\b', 'CREDIT_CARD', 0.88, 1)  # Amex format
# Last 4 of card
add_pattern(r'(?:ending\s+in|last\s+4|xxxx)[:\s]*(\d{4})\b', 'CREDIT_CARD_PARTIAL', 0.82, 1, re.I)
# VEHICLE IDENTIFIERS (HIPAA Required)
# === VIN (Vehicle Identification Number) ===
# 17 characters: A-Z (except I, O, Q) and 0-9
# Position 9 is check digit, position 10 is model year
# Common in accident/injury records, insurance claims
add_pattern(r'(?:VIN|Vehicle\s*(?:ID|Identification)(?:\s*Number)?)[:\s#]+([A-HJ-NPR-Z0-9]{17})\b', 'VIN', 0.96, 1, re.I)
# Bare VIN with word boundary - must be exactly 17 valid VIN characters
add_pattern(r'\b([A-HJ-NPR-Z0-9]{17})\b', 'VIN', 0.75, 1)

# === License Plate ===
add_pattern(r'(?:License\s*Plate|Plate\s*(?:Number|No|#)|Tag)[:\s#]+([A-Z0-9]{2,8})', 'LICENSE_PLATE', 0.88, 1, re.I)

# State-specific license plate formats (high confidence)
# California: 1ABC234 (1 digit, 3 letters, 3 digits)
add_pattern(r'\b(\d[A-Z]{3}\d{3})\b', 'LICENSE_PLATE', 0.82, 1)
# New York: ABC-1234 (3 letters, 4 digits with dash)
add_pattern(r'\b([A-Z]{3}-\d{4})\b', 'LICENSE_PLATE', 0.85, 1)
# Texas: ABC-1234 or ABC 1234
add_pattern(r'\b([A-Z]{3}[-\s]\d{4})\b', 'LICENSE_PLATE', 0.82, 1)
# Florida: ABC D12 or ABCD12 (letter-heavy)
add_pattern(r'\b([A-Z]{3,4}\s?[A-Z]?\d{2})\b', 'LICENSE_PLATE', 0.75, 1)


# ============================================================================
# HEALTHCARE-SPECIFIC IDENTIFIERS
# ============================================================================

# === NDC (National Drug Code) - 5-4-2 format with dashes ===
# FDA standard drug identifier, reveals medication info
add_pattern(r'\b(\d{5}-\d{4}-\d{2})\b', 'NDC', 0.92, 1)
# NDC with label
add_pattern(r'(?:NDC|National\s+Drug\s+Code)[:\s#]+(\d{5}-?\d{4}-?\d{2})', 'NDC', 0.95, 1, re.I)
# 10-digit NDC without dashes (some formats)
add_pattern(r'(?:NDC)[:\s#]+(\d{10,11})\b', 'NDC', 0.88, 1, re.I)

# === Room/Bed Numbers ===
# Hospital room numbers - require context
add_pattern(r'(?:Room|Rm\.?|Unit)[:\s#]+(\d{1,4}[A-Z]?)\b', 'ROOM_NUMBER', 0.88, 1, re.I)
add_pattern(r'(?:Bed|Bay)[:\s#]+(\d{1,2}[A-Z]?)\b', 'BED_NUMBER', 0.88, 1, re.I)
# Combined: "Room 412, Bed 3" or "Room 412-B"
add_pattern(r'(?:Room|Rm\.?)\s*(\d{1,4}[-]?[A-Z]?),?\s*(?:Bed|Bay)\s*(\d{1,2}[A-Z]?)', 'ROOM_NUMBER', 0.90, 0, re.I)
# Floor + Room: "4th floor, room 412" or "Floor 4 Room 12"
add_pattern(r'(?:Floor|Fl\.?)\s*(\d{1,2})\s*[,\s]+(?:Room|Rm\.?)\s*(\d{1,4})', 'ROOM_NUMBER', 0.85, 0, re.I)

# === Pager Numbers ===
add_pattern(r'(?:Pager|Beeper|Pgr\.?)[:\s#]+(\d{3}[-.\s]?\d{3}[-.\s]?\d{4})', 'PAGER', 0.90, 1, re.I)
add_pattern(r'(?:Pager|Pgr\.?)[:\s#]+(\d{4,7})\b', 'PAGER', 0.85, 1, re.I)  # Short pager codes

# === Extension Numbers ===
add_pattern(r'(?:ext\.?|extension|x)[:\s#]*(\d{3,6})\b', 'PHONE_EXT', 0.85, 1, re.I)
# Phone with extension: "555-1234 ext 567"
add_pattern(r'(\d{3}[-.\s]?\d{3}[-.\s]?\d{4})\s*(?:ext\.?|x)\s*(\d{3,6})', 'PHONE', 0.90, 0, re.I)

# === Prior Authorization / Claim Numbers ===
add_pattern(r'(?:Prior\s*Auth(?:orization)?|PA)[:\s#]+([A-Z0-9]{6,20})', 'AUTH_NUMBER', 0.90, 1, re.I)
add_pattern(r'(?:Auth(?:orization)?\s*(?:Number|No|#|Code))[:\s#]+([A-Z0-9]{6,20})', 'AUTH_NUMBER', 0.88, 1, re.I)
add_pattern(r'(?:Pre-?cert(?:ification)?)[:\s#]+([A-Z0-9]{6,20})', 'AUTH_NUMBER', 0.88, 1, re.I)
# Workers comp claim
add_pattern(r'(?:Workers?\s*Comp|WC)\s*(?:Claim)?[:\s#]+([A-Z0-9]{6,20})', 'CLAIM_NUMBER', 0.88, 1, re.I)


# ============================================================================
# PHYSICAL IDENTIFIERS (with strong context to avoid FPs)
# ============================================================================

# === Blood Type ===
add_pattern(r'(?:Blood\s*Type|Blood\s*Group|ABO)[:\s]+([ABO]{1,2}[+-])', 'BLOOD_TYPE', 0.92, 1, re.I)
add_pattern(r'(?:Type)[:\s]+([ABO]{1,2}[+-])(?:\s+blood|\s+Rh)', 'BLOOD_TYPE', 0.88, 1, re.I)

# === Height (with context) ===
add_pattern(r'(?:Height|Ht\.?)[:\s]+(\d{1,2}[\'′]\s*\d{1,2}[\"″]?)', 'HEIGHT', 0.90, 1, re.I)  # 5'10" format
add_pattern(r'(?:Height|Ht\.?)[:\s]+(\d{2,3})\s*(?:cm|in(?:ches)?)', 'HEIGHT', 0.88, 1, re.I)  # metric/inches
add_pattern(r'(?:Height|Ht\.?)[:\s]+(\d\s*ft\.?\s*\d{1,2}\s*in\.?)', 'HEIGHT', 0.88, 1, re.I)  # "5 ft 10 in"

# === Weight (with context) ===
add_pattern(r'(?:Weight|Wt\.?)[:\s]+(\d{2,3})\s*(?:lbs?|pounds?|kg|kilograms?)', 'WEIGHT', 0.88, 1, re.I)
add_pattern(r'(?:Weight|Wt\.?)[:\s]+(\d{2,3}(?:\.\d)?)\s*(?:lbs?|kg)', 'WEIGHT', 0.88, 1, re.I)

# === BMI (with context) ===
add_pattern(r'(?:BMI|Body\s*Mass\s*Index)[:\s]+(\d{2}(?:\.\d{1,2})?)', 'BMI', 0.90, 1, re.I)


# ============================================================================
# GEOGRAPHIC IDENTIFIERS
# ============================================================================

# === GPS Coordinates ===
# Decimal degrees: 41.8781, -87.6298 or 41.8781° N, 87.6298° W
add_pattern(r'(-?\d{1,3}\.\d{4,8})[,\s]+(-?\d{1,3}\.\d{4,8})', 'GPS_COORDINATES', 0.88, 0)
add_pattern(r'(\d{1,3}\.\d{4,8})°?\s*[NS][,\s]+(\d{1,3}\.\d{4,8})°?\s*[EW]', 'GPS_COORDINATES', 0.92, 0, re.I)
# DMS format: 41°52'43"N 87°37'47"W
add_pattern(r'(\d{1,3}°\d{1,2}[\'′]\d{1,2}[\"″]?[NS])\s*(\d{1,3}°\d{1,2}[\'′]\d{1,2}[\"″]?[EW])', 'GPS_COORDINATES', 0.90, 0)
# With label
add_pattern(r'(?:GPS|Coordinates?|Location|Lat(?:itude)?[/,]\s*Lon(?:gitude)?)[:\s]+(.{10,40})', 'GPS_COORDINATES', 0.85, 1, re.I)


# ============================================================================
# INTERNATIONAL IDENTIFIERS (with context/checksums)
# ============================================================================

# === UK NHS Number (10 digits with checksum) ===
add_pattern(r'(?:NHS|National\s+Health)[:\s#]+(\d{3}\s?\d{3}\s?\d{4})', 'NHS_NUMBER', 0.92, 1, re.I)
add_pattern(r'(?:NHS)[:\s#]+(\d{10})\b', 'NHS_NUMBER', 0.90, 1, re.I)

# === Canadian SIN (9 digits, starts with specific digits) ===
add_pattern(r'(?:SIN|Social\s+Insurance)[:\s#]+(\d{3}[-\s]?\d{3}[-\s]?\d{3})', 'SIN', 0.92, 1, re.I)
# Bare SIN with Canadian context (require word boundary for CA to avoid matching "Call")
add_pattern(r'(?:\bCanada\b|\bCanadian\b|\bCA\b)[^.]{0,30}(\d{3}[-\s]?\d{3}[-\s]?\d{3})', 'SIN', 0.80, 1, re.I)

# === Australian TFN (Tax File Number - 8-9 digits) ===
add_pattern(r'(?:TFN|Tax\s+File)[:\s#]+(\d{3}\s?\d{3}\s?\d{2,3})', 'TFN', 0.92, 1, re.I)

# === Indian Aadhaar (12 digits with specific format) ===
add_pattern(r'(?:Aadhaar|UIDAI|Aadhar)[:\s#]+(\d{4}\s?\d{4}\s?\d{4})', 'AADHAAR', 0.92, 1, re.I)
add_pattern(r'(?:Aadhaar|UIDAI)[:\s#]+(\d{12})\b', 'AADHAAR', 0.90, 1, re.I)

# === Mexican CURP (18 alphanumeric, specific format) ===
add_pattern(r'(?:CURP)[:\s#]+([A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d)', 'CURP', 0.95, 1, re.I)

# === German Sozialversicherungsnummer (12 digits) ===
add_pattern(r'(?:Sozialversicherungsnummer|SVNR|SV-Nummer)[:\s#]+(\d{2}\s?\d{6}\s?[A-Z]\s?\d{3})', 'SVNR', 0.92, 1, re.I)


