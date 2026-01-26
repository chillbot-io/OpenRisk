"""
OpenLabels Entity Registry.

Canonical entity types with weights, categories, and vendor mappings.
This is the single source of truth for entity classification.

Adapters MUST use normalize_type() to convert vendor-specific types.
Scorer MUST use get_weight() to look up entity weights.
"""

from typing import Dict, Optional


# =============================================================================
# ENTITY WEIGHTS (1-10 scale per spec)
# =============================================================================

ENTITY_WEIGHTS: Dict[str, int] = {
    # Direct Identifiers (8-10)
    "SSN": 10,
    "PASSPORT": 10,
    "DRIVERS_LICENSE": 7,
    "STATE_ID": 7,
    "TAX_ID": 8,
    "AADHAAR": 10,
    "NHS_NUMBER": 8,
    "MEDICARE_ID": 8,
    "MBI": 8,
    "HICN": 8,
    "A_NUMBER": 10,
    "GREEN_CARD_NUMBER": 10,
    "VISA_NUMBER": 8,

    # Healthcare / PHI (5-8)
    "MRN": 8,
    "HEALTH_PLAN_ID": 8,
    "NPI": 7,
    "DEA": 7,
    "DIAGNOSIS": 8,
    "MEDICATION": 6,
    "LAB_TEST": 5,
    "ENCOUNTER_ID": 5,

    # Personal Information (2-8)
    "NAME": 5,
    "NAME_PATIENT": 8,
    "NAME_PROVIDER": 4,
    "DATE_DOB": 6,
    "DOB": 6,
    "DATE": 3,
    "AGE": 4,
    "GENDER": 2,
    "ETHNICITY": 4,
    "RELIGION": 4,
    "EMPLOYER": 4,
    "PROFESSION": 3,

    # Contact Information (2-5)
    "EMAIL": 5,
    "PHONE": 4,
    "ADDRESS": 5,
    "ZIP": 3,
    "CITY": 2,
    "STATE": 2,
    "LOCATION": 3,

    # Financial (5-10)
    "CREDIT_CARD": 10,
    "BANK_ACCOUNT": 7,
    "BANK_ROUTING": 6,
    "IBAN": 7,
    "SWIFT_BIC": 5,
    "CUSIP": 5,
    "ISIN": 5,
    "BITCOIN_ADDRESS": 8,
    "ETHEREUM_ADDRESS": 8,
    "CRYPTO_SEED_PHRASE": 10,

    # Digital Identifiers (3-6)
    "IP_ADDRESS": 4,
    "MAC_ADDRESS": 4,
    "URL": 3,
    "USERNAME": 5,
    "DEVICE_ID": 5,
    "IMEI": 6,
    "VIN": 5,

    # Credentials & Secrets (8-10)
    "PASSWORD": 10,
    "API_KEY": 10,
    "SECRET": 10,
    "PRIVATE_KEY": 10,
    "JWT": 8,
    "BEARER_TOKEN": 8,
    "DATABASE_URL": 10,
    "AWS_ACCESS_KEY": 10,
    "AWS_SECRET_KEY": 10,
    "AZURE_STORAGE_KEY": 10,
    "AZURE_CONNECTION_STRING": 10,
    "AZURE_SQL_CONNECTION": 10,
    "AZURE_SAS_TOKEN": 8,
    "GCP_CREDENTIALS": 10,
    "GCP_API_KEY": 10,
    "GOOGLE_OAUTH_SECRET": 10,
    "GITHUB_TOKEN": 10,
    "GITLAB_TOKEN": 10,
    "SLACK_TOKEN": 10,
    "SLACK_WEBHOOK": 8,
    "DISCORD_TOKEN": 10,
    "STRIPE_KEY": 10,
    "TWILIO_TOKEN": 10,
    "SENDGRID_KEY": 10,
    "OPENAI_API_KEY": 10,
    "ANTHROPIC_API_KEY": 10,
    "HUGGINGFACE_TOKEN": 10,

    # Government & Classification (7-10)
    "CLASSIFICATION_LEVEL": 8,
    "CLASSIFICATION_MARKING": 10,
    "SCI_MARKING": 10,
    "ITAR_MARKING": 8,
    "CAGE_CODE": 4,

    # International IDs (7-10)
    "SIN_CA": 10,
    "NINO_UK": 8,
    "UTR_UK": 8,
    "INSEE_FR": 8,
    "PERSONALAUSWEIS_DE": 8,
    "CODICE_FISCALE_IT": 8,
    "DNI_ES": 8,
    "CPF_BR": 10,
    "RG_BR": 8,
    "CURP_MX": 8,
    "AADHAAR_IN": 10,
    "PAN_IN": 8,
    "TFN_AU": 8,
    "MY_NRIC": 8,
    "CHINA_RESIDENT_ID": 10,
    "JAPAN_MY_NUMBER": 10,
}

# Default weight for unknown entity types
DEFAULT_WEIGHT = 5


# =============================================================================
# ENTITY CATEGORIES (for co-occurrence rules)
# =============================================================================

ENTITY_CATEGORIES: Dict[str, str] = {
    # Direct identifiers
    "SSN": "direct_identifier",
    "PASSPORT": "direct_identifier",
    "DRIVERS_LICENSE": "direct_identifier",
    "STATE_ID": "direct_identifier",
    "TAX_ID": "direct_identifier",
    "AADHAAR": "direct_identifier",
    "AADHAAR_IN": "direct_identifier",
    "A_NUMBER": "direct_identifier",
    "GREEN_CARD_NUMBER": "direct_identifier",
    "SIN_CA": "direct_identifier",
    "NINO_UK": "direct_identifier",
    "INSEE_FR": "direct_identifier",
    "CPF_BR": "direct_identifier",
    "CHINA_RESIDENT_ID": "direct_identifier",
    "JAPAN_MY_NUMBER": "direct_identifier",

    # Healthcare
    "MRN": "health_info",
    "HEALTH_PLAN_ID": "health_info",
    "NPI": "health_info",
    "DEA": "health_info",
    "DIAGNOSIS": "health_info",
    "MEDICATION": "health_info",
    "LAB_TEST": "health_info",
    "MBI": "health_info",
    "HICN": "health_info",
    "MEDICARE_ID": "health_info",
    "NHS_NUMBER": "health_info",

    # Financial
    "CREDIT_CARD": "financial",
    "BANK_ACCOUNT": "financial",
    "BANK_ROUTING": "financial",
    "IBAN": "financial",
    "SWIFT_BIC": "financial",
    "BITCOIN_ADDRESS": "financial",
    "ETHEREUM_ADDRESS": "financial",
    "CRYPTO_SEED_PHRASE": "financial",

    # Contact
    "EMAIL": "contact",
    "PHONE": "contact",
    "ADDRESS": "contact",
    "ZIP": "contact",
    "CITY": "contact",
    "LOCATION": "contact",

    # Quasi-identifiers
    "NAME": "quasi_identifier",
    "DATE_DOB": "quasi_identifier",
    "DOB": "quasi_identifier",
    "AGE": "quasi_identifier",
    "GENDER": "quasi_identifier",
    "ETHNICITY": "quasi_identifier",

    # Credentials
    "PASSWORD": "credential",
    "API_KEY": "credential",
    "SECRET": "credential",
    "PRIVATE_KEY": "credential",
    "JWT": "credential",
    "AWS_ACCESS_KEY": "credential",
    "AWS_SECRET_KEY": "credential",
    "AZURE_STORAGE_KEY": "credential",
    "AZURE_CONNECTION_STRING": "credential",
    "AZURE_SQL_CONNECTION": "credential",
    "GCP_CREDENTIALS": "credential",
    "GITHUB_TOKEN": "credential",
    "SLACK_TOKEN": "credential",
    "STRIPE_KEY": "credential",
    "DATABASE_URL": "credential",
    "OPENAI_API_KEY": "credential",
    "ANTHROPIC_API_KEY": "credential",

    # Classification
    "CLASSIFICATION_LEVEL": "classification_marking",
    "CLASSIFICATION_MARKING": "classification_marking",
    "SCI_MARKING": "classification_marking",
    "ITAR_MARKING": "classification_marking",
}


# =============================================================================
# VENDOR TYPE MAPPINGS
# All vendor-specific types map to canonical OpenLabels types
# =============================================================================

VENDOR_ALIASES: Dict[str, str] = {
    # ----- AWS Macie -----
    "AWS_CREDENTIALS": "AWS_ACCESS_KEY",
    "OPENSSH_PRIVATE_KEY": "PRIVATE_KEY",
    "PGP_PRIVATE_KEY": "PRIVATE_KEY",
    "PKCS": "PRIVATE_KEY",
    "PUTTY_PRIVATE_KEY": "PRIVATE_KEY",
    "CREDIT_CARD_NUMBER": "CREDIT_CARD",
    "USA_SOCIAL_SECURITY_NUMBER": "SSN",
    "USA_PASSPORT_NUMBER": "PASSPORT",
    "USA_DRIVER_LICENSE": "DRIVERS_LICENSE",
    "BANK_ACCOUNT_NUMBER": "BANK_ACCOUNT",
    "CA_SOCIAL_INSURANCE_NUMBER": "SIN_CA",
    "UK_NATIONAL_INSURANCE_NUMBER": "NINO_UK",
    "DATE_OF_BIRTH": "DOB",
    "EMAIL_ADDRESS": "EMAIL",
    "NAME": "NAME",
    "PHONE_NUMBER": "PHONE",
    "USA_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER": "TAX_ID",
    "USA_MEDICARE_BENEFICIARY_IDENTIFIER": "MBI",
    "USA_HEALTH_INSURANCE_CLAIM_NUMBER": "HICN",
    "USA_NATIONAL_PROVIDER_IDENTIFIER": "NPI",
    "USA_DRUG_ENFORCEMENT_AGENCY_NUMBER": "DEA",
    "VEHICLE_IDENTIFICATION_NUMBER": "VIN",
    "UK_UNIQUE_TAXPAYER_REFERENCE": "UTR_UK",
    "FRANCE_NATIONAL_IDENTIFICATION_NUMBER": "INSEE_FR",
    "GERMANY_NATIONAL_IDENTIFICATION_NUMBER": "PERSONALAUSWEIS_DE",
    "ITALY_NATIONAL_IDENTIFICATION_NUMBER": "CODICE_FISCALE_IT",
    "SPAIN_NATIONAL_IDENTIFICATION_NUMBER": "DNI_ES",
    "BRAZIL_CPF_NUMBER": "CPF_BR",

    # ----- GCP DLP -----
    "US_SOCIAL_SECURITY_NUMBER": "SSN",
    "US_PASSPORT": "PASSPORT",
    "US_DRIVERS_LICENSE_NUMBER": "DRIVERS_LICENSE",
    "US_BANK_ROUTING_MICR": "BANK_ROUTING",
    "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER": "TAX_ID",
    "US_EMPLOYER_IDENTIFICATION_NUMBER": "TAX_ID",
    "US_HEALTHCARE_NPI": "NPI",
    "US_DEA_NUMBER": "DEA",
    "US_MEDICARE_BENEFICIARY_ID_NUMBER": "MBI",
    "US_VEHICLE_IDENTIFICATION_NUMBER": "VIN",
    "CANADA_SOCIAL_INSURANCE_NUMBER": "SIN_CA",
    "UK_NATIONAL_INSURANCE_NUMBER": "NINO_UK",
    "UK_TAXPAYER_REFERENCE": "UTR_UK",
    "UK_NATIONAL_HEALTH_SERVICE_NUMBER": "NHS_NUMBER",
    "FRANCE_NIR": "INSEE_FR",
    "GERMANY_IDENTITY_CARD_NUMBER": "PERSONALAUSWEIS_DE",
    "ITALY_FISCAL_CODE": "CODICE_FISCALE_IT",
    "SPAIN_NIE_NUMBER": "DNI_ES",
    "SPAIN_DNI_NUMBER": "DNI_ES",
    "BRAZIL_CPF_NUMBER": "CPF_BR",
    "MEXICO_CURP_NUMBER": "CURP_MX",
    "INDIA_AADHAAR_INDIVIDUAL": "AADHAAR_IN",
    "INDIA_PAN_INDIVIDUAL": "PAN_IN",
    "AUSTRALIA_TAX_FILE_NUMBER": "TFN_AU",
    "JAPAN_MY_NUMBER": "JAPAN_MY_NUMBER",
    "CHINA_RESIDENT_ID_NUMBER": "CHINA_RESIDENT_ID",
    "IBAN_CODE": "IBAN",
    "SWIFT_CODE": "SWIFT_BIC",
    "PERSON_NAME": "NAME",
    "STREET_ADDRESS": "ADDRESS",
    "GCP_CREDENTIALS": "GCP_CREDENTIALS",
    "GCP_API_KEY": "GCP_API_KEY",
    "JSON_WEB_TOKEN": "JWT",
    "HTTP_COOKIE": "SECRET",
    "XSRF_TOKEN": "SECRET",
    "AUTH_TOKEN": "BEARER_TOKEN",
    "ENCRYPTION_KEY": "SECRET",
    "IMEI_HARDWARE_ID": "IMEI",
    "ETHNIC_GROUP": "ETHNICITY",

    # ----- Azure Purview -----
    "U.S. Social Security Number (SSN)": "SSN",
    "U.S. / U.K. Passport Number": "PASSPORT",
    "U.S. Driver's License Number": "DRIVERS_LICENSE",
    "U.S. Bank Account Number": "BANK_ACCOUNT",
    "U.S. Individual Taxpayer Identification Number (ITIN)": "TAX_ID",
    "Credit Card Number": "CREDIT_CARD",
    "International Banking Account Number (IBAN)": "IBAN",
    "SWIFT Code": "SWIFT_BIC",
    "Canada Social Insurance Number": "SIN_CA",
    "U.K. National Insurance Number (NINO)": "NINO_UK",
    "U.K. National Health Service Number": "NHS_NUMBER",
    "France National ID Card (CNI)": "INSEE_FR",
    "France Social Security Number (INSEE)": "INSEE_FR",
    "Germany Identity Card Number": "PERSONALAUSWEIS_DE",
    "Germany Tax Identification Number": "PERSONALAUSWEIS_DE",
    "Italy Fiscal Code": "CODICE_FISCALE_IT",
    "Spain DNI": "DNI_ES",
    "Spain Social Security Number": "DNI_ES",
    "Brazil CPF Number": "CPF_BR",
    "Brazil National ID Card (RG)": "RG_BR",
    "Mexico CURP": "CURP_MX",
    "India Permanent Account Number (PAN)": "PAN_IN",
    "India Unique Identification (Aadhaar) Number": "AADHAAR_IN",
    "Australia Tax File Number": "TFN_AU",
    "Japan My Number - Personal": "JAPAN_MY_NUMBER",
    "China Resident Identity Card Number": "CHINA_RESIDENT_ID",
    "Malaysia Identity Card Number": "MY_NRIC",
    "Email": "EMAIL",
    "Phone Number": "PHONE",
    "Person's Name": "NAME",
    "Address": "ADDRESS",
    "Date of Birth": "DOB",
    "Azure Storage Account Key": "AZURE_STORAGE_KEY",
    "Azure SQL Connection String": "AZURE_SQL_CONNECTION",
    "Azure Service Bus Connection String": "AZURE_CONNECTION_STRING",
    "Azure IoT Connection String": "AZURE_CONNECTION_STRING",
    "Azure Cosmos DB Connection String": "AZURE_CONNECTION_STRING",
    "Azure Redis Cache Connection String": "AZURE_CONNECTION_STRING",
    "Azure SAS Token": "AZURE_SAS_TOKEN",
    "Azure AD Client Secret": "SECRET",
    "General Password": "PASSWORD",
    "IP Address": "IP_ADDRESS",
    "IPv4 Address": "IP_ADDRESS",
    "IPv6 Address": "IP_ADDRESS",
    "MAC Address": "MAC_ADDRESS",
    "URL": "URL",
}


# =============================================================================
# PUBLIC API
# =============================================================================

def get_weight(entity_type: str) -> int:
    """
    Get weight for an entity type.

    Args:
        entity_type: Canonical entity type (e.g., "SSN", "CREDIT_CARD")

    Returns:
        Weight from 1-10, or DEFAULT_WEIGHT if unknown
    """
    return ENTITY_WEIGHTS.get(entity_type, DEFAULT_WEIGHT)


def get_category(entity_type: str) -> str:
    """
    Get category for an entity type.

    Args:
        entity_type: Canonical entity type

    Returns:
        Category string, or "unknown" if not categorized
    """
    return ENTITY_CATEGORIES.get(entity_type, "unknown")


def normalize_type(vendor_type: str, source: Optional[str] = None) -> str:
    """
    Normalize a vendor-specific entity type to canonical OpenLabels type.

    Args:
        vendor_type: Entity type from Macie, DLP, Purview, or scanner
        source: Optional source hint (unused, for logging)

    Returns:
        Canonical OpenLabels entity type
    """
    # Already canonical?
    if vendor_type in ENTITY_WEIGHTS:
        return vendor_type

    # Check vendor aliases
    if vendor_type in VENDOR_ALIASES:
        return VENDOR_ALIASES[vendor_type]

    # Unknown - pass through as-is
    return vendor_type


def is_known_type(entity_type: str) -> bool:
    """Check if an entity type is in the registry."""
    return entity_type in ENTITY_WEIGHTS or entity_type in VENDOR_ALIASES
