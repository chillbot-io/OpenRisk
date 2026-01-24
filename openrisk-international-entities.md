# OpenRisk International Entity Types

**Proposed Additions for Global Coverage**

This document defines international entity types to be added to OpenRisk v1.0, enabling users from any country to classify and score their sensitive data. Entities are organized by region with format specifications for detection pattern development.

---

## Summary of Additions

| Region | New Entity Types |
|--------|------------------|
| Americas | 14 |
| Europe | 22 |
| Asia-Pacific | 18 |
| Middle East & Africa | 6 |
| **Total** | **60** |

Combined with existing ~130 types = **~190 total entity types**

---

## Americas

### Brazil

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `BR_CPF` | **9** | `NNN.NNN.NNN-NN` (11 digits) | Cadastro de Pessoas Físicas - Individual taxpayer ID. Last 2 digits are check digits (mod 11). Universal identifier since 2023. |
| `BR_RG` | **8** | Varies by state (7-9 digits + issuer) | Registro Geral - National ID card number |
| `BR_CNPJ` | **6** | `NN.NNN.NNN/NNNN-NN` (14 digits) | Corporate taxpayer ID |
| `BR_PIS_PASEP` | **7** | `NNN.NNNNN.NN-N` (11 digits) | Social integration program number (employment) |
| `BR_CNS` | **7** | 15 digits | Cartão Nacional de Saúde - National health card |

**Detection notes:**
- CPF uses mod 11 check digit algorithm
- First 8 digits of CPF indicate registration region

### Canada

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `CA_SIN` | **9** | `NNN-NNN-NNN` (9 digits) | Social Insurance Number. Luhn checksum. First digit indicates province (1=Atlantic, 4-5=Ontario, 6=Prairies, 7=BC, 9=Temporary residents). |
| `CA_PHN` | **7** | Varies by province | Provincial Health Number |
| `CA_OHIP` | **7** | `NNNN-NNN-NNN` + 2-char version | Ontario Health Insurance Plan number |
| `CA_BC_PHN` | **7** | `NNNN-NNN-NNN` (10 digits) | British Columbia Personal Health Number |
| `CA_QUEBEC_HIN` | **7** | `AAAA NNNN NNNN` | Quebec Health Insurance Number (RAMQ) |

**Detection notes:**
- SIN starting with 9 = temporary resident (time-limited)
- Provincial health numbers have different formats per province

### Mexico

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `MX_CURP` | **9** | 18 alphanumeric | Clave Única de Registro de Población - Universal ID. Format: `XXXXYYMMDDXSSXXXXX` where XX=name chars, YYMMDD=DOB, X=gender (H/M), SS=state code. |
| `MX_RFC` | **8** | 12-13 alphanumeric | Registro Federal de Contribuyentes - Tax ID. 13 chars for individuals, 12 for companies. |
| `MX_NSS` | **7** | 11 digits | Número de Seguridad Social - Social security number |
| `MX_CLABE` | **7** | 18 digits | Standardized bank account number |

**Detection notes:**
- CURP last digit is check digit
- RFC first 10 chars match CURP for individuals

### Argentina

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `AR_DNI` | **9** | 7-8 digits | Documento Nacional de Identidad |
| `AR_CUIT` | **8** | `NN-NNNNNNNN-N` (11 digits) | Tax ID. Prefix: 20=male, 27=female, 30/33=company. Middle 8=DNI. Last=check digit. |
| `AR_CUIL` | **7** | `NN-NNNNNNNN-N` (11 digits) | Labor/social security ID (same format as CUIT) |

---

## Europe

### United Kingdom

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `UK_NHS_NUMBER` | **8** | `NNN NNN NNNN` (10 digits) | NHS Number (England, Wales, Isle of Man). Mod 11 check digit. Range: 400M-499M, 600M-799M. |
| `UK_CHI` | **8** | `DDMMYY NNNN` (10 digits) | Community Health Index (Scotland). First 6 = DOB, 9th digit = gender (odd=male, even=female). |
| `UK_HC_NUMBER` | **8** | 10 digits (range 320M-399M) | Health & Care Number (Northern Ireland) |
| `UK_NINO` | **8** | `AA NNNNNN A` | National Insurance Number. Format: 2 letters + 6 digits + 1 letter. |
| `UK_UTR` | **7** | 10 digits | Unique Taxpayer Reference |

**Detection notes:**
- NHS/CHI/H&C all use mod 11 check digit
- Can distinguish by range: 01-31 prefix = Scotland CHI, 32-39 = Northern Ireland
- NHS numbers 999 000 0000 - 999 999 9999 reserved for testing

### Germany

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `DE_STEUER_ID` | **8** | 11 digits | Steuerliche Identifikationsnummer - Personal tax ID (issued at birth) |
| `DE_SVNR` | **7** | 12 alphanumeric | Sozialversicherungsnummer - Social insurance number |
| `DE_PERSONALAUSWEIS` | **8** | 10 alphanumeric | National ID card number |
| `DE_KVNR` | **7** | 10 alphanumeric | Krankenversichertennummer - Health insurance number |

### France

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `FR_INSEE` | **9** | 15 digits | Numéro de sécurité sociale (NIR). Format: `S XX MM DDD CCC NNN KK` where S=sex, XX=birth year, MM=month, DDD=dept, CCC=commune, NNN=serial, KK=check. |
| `FR_NIF` | **8** | 13 digits | Numéro d'Identification Fiscale - Tax ID |
| `FR_CARTE_VITALE` | **7** | 15 digits | Health insurance card number (same as INSEE) |

**Detection notes:**
- First digit: 1=male, 2=female
- INSEE includes birth location encoded in digits 6-10

### Italy

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `IT_CODICE_FISCALE` | **9** | 16 alphanumeric | Fiscal code. Contains surname (3), name (3), birth year (2), month (1 letter), day+gender (2), municipality (4), check (1). |
| `IT_TESSERA_SANITARIA` | **7** | 20 digits | Health card number |
| `IT_PARTITA_IVA` | **6** | 11 digits | VAT number |

**Detection notes:**
- Codice Fiscale encodes personal data - can derive name, DOB, birthplace
- Day field: males = day (01-31), females = day + 40 (41-71)

### Spain

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `ES_DNI` | **9** | `NNNNNNNN-A` (8 digits + letter) | Documento Nacional de Identidad. Check letter from mod 23 lookup table. |
| `ES_NIE` | **8** | `X-NNNNNNN-A` (letter + 7 digits + letter) | Foreigner ID. Prefix: X, Y, or Z. |
| `ES_NIF` | **8** | 8 digits + letter OR letter + 7 digits + letter | Tax ID (same as DNI for citizens, NIE for foreigners) |
| `ES_NSS` | **7** | 12 digits | Social security number |

**Detection notes:**
- DNI check letter: divide number by 23, use remainder to lookup in "TRWAGMYFPDXBNJZSQVHLCKE"

### Netherlands

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `NL_BSN` | **9** | 9 digits | Burgerservicenummer - Citizen service number. Mod 11 check. Does not encode any personal info. |
| `NL_BTW` | **6** | `NL` + 9 digits + `B` + 2 digits | VAT number |

### Poland

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `PL_PESEL` | **9** | 11 digits | Universal Electronic System for Registration of the Population. Format: `YYMMDDSSSSQ` where YYMMDD=DOB (century encoded in month), SSSS=serial (last digit=gender), Q=check. |
| `PL_NIP` | **7** | 10 digits | Tax ID |
| `PL_DOWOD` | **8** | 3 letters + 6 digits | National ID card number |

**Detection notes:**
- PESEL month encoding: Jan-Dec = 01-12 for 1900s, 21-32 for 2000s, 41-52 for 2100s
- Last digit of serial: odd=male, even=female

### Other EU

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `AT_SVNR` | **8** | 10 digits | Austria - Social insurance number (first 3 = serial, 4th = check, last 6 = DOB) |
| `BE_RIJKSREGISTER` | **9** | 11 digits | Belgium - National Register Number. YY.MM.DD-SSS.CC format |
| `CH_AHV` | **8** | 13 digits (756.XXXX.XXXX.XX) | Switzerland - Social security number |
| `CZ_RODNE_CISLO` | **9** | 9-10 digits | Czech Republic - Birth number. YYMMDD/SSSC format |
| `DK_CPR` | **9** | 10 digits (DDMMYY-SSSS) | Denmark - Central Person Register |
| `FI_HETU` | **9** | 11 chars (DDMMYY-SSSC) | Finland - Personal identity code |
| `GR_AMKA` | **8** | 11 digits | Greece - Social security number |
| `IE_PPS` | **9** | 7 digits + 1-2 letters | Ireland - Personal Public Service Number |
| `NO_FODSELSNUMMER` | **9** | 11 digits | Norway - Birth number (DDMMYY + 5 digits) |
| `PT_NIF` | **8** | 9 digits | Portugal - Tax ID |
| `SE_PERSONNUMMER` | **9** | 12 digits (YYYYMMDD-XXXX) | Sweden - Personal identity number |

---

## Asia-Pacific

### China

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `CN_RESIDENT_ID` | **9** | 18 digits | 居民身份证号码. Format: 6 (region) + 8 (DOB YYYYMMDD) + 3 (serial, gender in last) + 1 (check). Required for citizens 16+. |
| `CN_PASSPORT` | **8** | E/G + 8 digits OR W + 8 alphanumeric | Chinese passport number |
| `CN_USCC` | **6** | 18 alphanumeric | Unified Social Credit Code (business) |

**Detection notes:**
- Check digit uses mod 11 with weights
- 17th digit: odd = male, even = female
- First 6 digits encode province/city/district

### Japan

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `JP_MY_NUMBER` | **9** | 12 digits (often displayed as NNNN NNNN NNNN) | Individual Number (マイナンバー). Issued to all residents since 2015. |
| `JP_PASSPORT` | **8** | 2 letters + 7 digits | Japanese passport number |
| `JP_DRIVING_LICENSE` | **8** | 12 digits | Japanese driver's license number |
| `JP_HEALTH_INSURANCE` | **7** | 8 digits | Health insurance card number (保険者番号) |
| `JP_JUKI_CARD` | **7** | 11 digits | Basic Resident Register card number (legacy, being replaced) |

### South Korea

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `KR_RRN` | **9** | `YYMMDD-NNNNNNN` (13 digits) | Resident Registration Number. 7th digit indicates century+gender: 1/2=1900s M/F, 3/4=2000s M/F, 5-8=foreigners. |
| `KR_PASSPORT` | **8** | M + 8 digits | Korean passport number |
| `KR_DRIVER_LICENSE` | **8** | 12 digits (2-2-6-2 format) | Korean driver's license |

**Detection notes:**
- RRN is highly sensitive in Korea - often partially masked
- Last digit is check digit (mod 11)

### India

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `IN_AADHAAR` | **9** | 12 digits (NNNN NNNN NNNN) | Aadhaar number. World's largest biometric ID system. Verhoeff checksum. |
| `IN_PAN` | **8** | 10 alphanumeric (AAAAA9999A) | Permanent Account Number (tax). 4th char indicates holder type. |
| `IN_PASSPORT` | **8** | 1 letter + 7 digits | Indian passport number |
| `IN_DRIVING_LICENSE` | **8** | Varies by state (typically 15-16 chars) | Indian driving license |
| `IN_VOTER_ID` | **7** | 3 letters + 7 digits | Electoral Photo ID Card (EPIC) |
| `IN_UAN` | **7** | 12 digits | Universal Account Number (provident fund) |

**Detection notes:**
- Aadhaar uses Verhoeff algorithm (not Luhn)
- PAN 4th character: P=Person, C=Company, H=HUF, F=Firm, etc.

### Singapore

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `SG_NRIC` | **9** | 1 letter + 7 digits + 1 letter | National Registration IC. Prefix: S/T=citizen/PR born before/after 2000. Check letter from mod 11. |
| `SG_FIN` | **8** | 1 letter + 7 digits + 1 letter | Foreign Identification Number. Prefix: F/G (before 2022), M (from 2022). |
| `SG_UEN` | **6** | 9-10 alphanumeric | Unique Entity Number (business) |

**Detection notes:**
- First 2 digits often = last 2 of birth year (for born 1968+)
- Check letter algorithm uses weights [2,7,6,5,4,3,2] for digits

### Malaysia

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `MY_NRIC` | **9** | `YYMMDD-PB-NNNG` (12 digits) | MyKad number. PB = place of birth code, G = gender (odd=male, even=female). |
| `MY_PASSPORT` | **8** | 1-2 letters + 7-8 digits | Malaysian passport number |
| `MY_ARMY_ID` | **7** | Alphanumeric | Malaysian armed forces ID |

**Detection notes:**
- No publicly known checksum
- PB codes 01-16 = Malaysian states, 17+ = foreign countries

### Indonesia

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `ID_NIK` | **9** | 16 digits | Nomor Induk Kependudukan. Format: PPRRSSDDMMYYXXXX where PP=province, RR=regency, SS=district, DDMMYY=DOB (females +40 to DD), XXXX=serial. |
| `ID_NPWP` | **8** | 15-16 digits | Tax ID |
| `ID_KK` | **7** | 16 digits | Family card number |

### Taiwan

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `TW_NATIONAL_ID` | **9** | 1 letter + 9 digits | National ID. First letter = region, 2nd digit = gender (1=male, 2=female). |
| `TW_ARC` | **8** | 1-2 letters + 8-10 digits | Alien Resident Certificate number |
| `TW_PASSPORT` | **8** | 9 digits | Taiwan passport number |

### Hong Kong

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `HK_HKID` | **9** | `A(N)NNNNNN(N)` - 1-2 letters + 6 digits + check | Hong Kong Identity Card. Check digit can be 0-9 or A. |
| `HK_PASSPORT` | **8** | H/K + 8 digits | HKSAR passport number |

**Detection notes:**
- Check digit algorithm: multiply each position by weight, mod 11
- A=10 when used as check digit

### Australia

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `AU_TFN` | **9** | 8-9 digits | Tax File Number. Mod 11 check algorithm. |
| `AU_MEDICARE` | **8** | 10-11 digits | Medicare card number |
| `AU_IHI` | **7** | 16 digits | Individual Healthcare Identifier |
| `AU_DRIVER_LICENSE` | **8** | Varies by state | Australian driver's license |
| `AU_PASSPORT` | **8** | 1-2 letters + 7 digits | Australian passport number |

### New Zealand

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `NZ_IRD` | **8** | 8-9 digits | Inland Revenue Department number (tax) |
| `NZ_NHI` | **7** | 3 letters + 4 alphanumeric | National Health Index number |
| `NZ_DRIVER_LICENSE` | **8** | 2 letters + 6 digits | NZ driver's license |
| `NZ_PASSPORT` | **8** | 2 letters + 6 digits | NZ passport number |

### Philippines

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `PH_PSN` | **9** | 12 digits | PhilSys Number (national ID, rolling out) |
| `PH_SSS` | **8** | 10 digits (NN-NNNNNNN-N) | Social Security System number |
| `PH_TIN` | **8** | 9-12 digits | Tax Identification Number |
| `PH_UMID` | **7** | 12 digits | Unified Multi-Purpose ID |

### Thailand

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `TH_NATIONAL_ID` | **9** | 13 digits | Thai National ID. Format: R-PPPP-NNNNN-NN-C where R=type, PPPP=province, NNNNN=amphoe+serial, C=check. |
| `TH_PASSPORT` | **8** | 2 letters + 7 digits | Thai passport number |

### Vietnam

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `VN_CCCD` | **9** | 12 digits | Căn cước công dân (new national ID since 2021) |
| `VN_CMND` | **8** | 9 or 12 digits | Chứng minh nhân dân (old ID, being phased out) |
| `VN_PASSPORT` | **8** | 1 letter + 7-8 digits | Vietnamese passport number |

---

## Middle East & Africa

### South Africa

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `ZA_ID` | **9** | 13 digits | South African ID. Format: YYMMDDSSSSCAZ. SSSS=gender (0000-4999=F, 5000-9999=M), C=citizenship (0=citizen, 1=PR, 2=refugee), Z=Luhn check. |
| `ZA_PASSPORT` | **8** | 1 letter + 8 digits | SA passport number |

**Detection notes:**
- Uses Luhn checksum
- Can extract DOB, gender, citizenship status from number

### Turkey

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `TR_TCKN` | **9** | 11 digits | TC Kimlik Numarası (Turkish ID). First digit never 0. Last 2 digits are check digits. |
| `TR_VKN` | **7** | 10 digits | Tax ID (Vergi Kimlik Numarası) |
| `TR_PASSPORT` | **8** | 1 letter + 7 digits | Turkish passport number |

### Israel

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `IL_ID` | **9** | 9 digits | Israeli ID number (Teudat Zehut). Luhn checksum. Leading zeros for numbers < 9 digits. |
| `IL_PASSPORT` | **8** | 7-9 digits | Israeli passport number |

### United Arab Emirates

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `AE_EMIRATES_ID` | **9** | 15 digits (784-YYYY-NNNNNNN-C) | Emirates ID. 784 = UAE country code, YYYY = birth year. |
| `AE_PASSPORT` | **8** | Alphanumeric | UAE passport number |

### Saudi Arabia

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `SA_NATIONAL_ID` | **9** | 10 digits | Saudi national ID (starts with 1 for citizens, 2 for residents) |
| `SA_IQAMA` | **8** | 10 digits (starts with 2) | Resident ID for non-citizens |

### Russia

| Entity Type | Weight | Format | Description |
|-------------|--------|--------|-------------|
| `RU_INN` | **8** | 10 digits (company) or 12 digits (individual) | Tax ID. Check digit validation with weights. |
| `RU_SNILS` | **8** | `NNN-NNN-NNN NN` (11 digits) | Social insurance number. Last 2 = checksum. |
| `RU_PASSPORT_INTERNAL` | **9** | `NN NN NNNNNN` (10 digits) | Internal passport (series + number) |
| `RU_PASSPORT_INTL` | **8** | `NN NNNNNNN` (9 digits) | International passport |

---

## Entity Type Naming Convention

All international entity types follow the pattern:
```
{ISO_COUNTRY_CODE}_{IDENTIFIER_NAME}
```

Examples:
- `BR_CPF` - Brazil CPF
- `UK_NHS_NUMBER` - UK NHS Number
- `JP_MY_NUMBER` - Japan My Number
- `ZA_ID` - South Africa ID

This allows:
1. Easy filtering by country
2. Clear namespace separation
3. Consistent naming across registry

---

## Detection Priority for v1

### Tier 1 - Implement First (High global coverage)

| Entity | Countries | Population Coverage |
|--------|-----------|---------------------|
| National IDs | All | Most world population |
| Tax IDs | All | Business critical |
| Healthcare IDs | US, UK, AU, CA, EU | Healthcare industry |

### Tier 2 - High Priority

| Entity | Rationale |
|--------|-----------|
| `BR_CPF` | 210M population, LGPD compliance |
| `IN_AADHAAR` | 1.4B population, world's largest biometric DB |
| `CN_RESIDENT_ID` | 1.4B population |
| `JP_MY_NUMBER` | Major economy |
| `KR_RRN` | Major economy |
| `UK_NHS_NUMBER`, `UK_NINO` | Major economy, post-Brexit UK GDPR |
| EU national IDs | GDPR compliance |

### Tier 3 - Extended Coverage

- Middle East identifiers
- African identifiers
- Southeast Asian identifiers
- Latin American identifiers (beyond Brazil/Mexico/Argentina)

---

## Validation Algorithms Summary

| Algorithm | Used By |
|-----------|---------|
| **Luhn** | CA_SIN, SG_NRIC, ZA_ID, IL_ID, many credit cards |
| **Mod 11** | UK_NHS_NUMBER, UK_CHI, BR_CPF, NL_BSN, PL_PESEL, KR_RRN |
| **Verhoeff** | IN_AADHAAR |
| **Custom weights** | IT_CODICE_FISCALE, ES_DNI, FR_INSEE, CN_RESIDENT_ID |

---

## Regulatory Mapping

| Regulation | Key Entity Types |
|------------|-----------------|
| **GDPR** (EU) | All EU national IDs, health IDs |
| **UK GDPR** | UK_NHS_NUMBER, UK_NINO, UK_CHI |
| **LGPD** (Brazil) | BR_CPF, BR_RG, BR_CNS |
| **PIPL** (China) | CN_RESIDENT_ID |
| **APPI** (Japan) | JP_MY_NUMBER |
| **PIPA** (Korea) | KR_RRN |
| **PDPA** (Singapore) | SG_NRIC, SG_FIN |
| **Privacy Act** (Australia) | AU_TFN, AU_MEDICARE |
| **PIPEDA** (Canada) | CA_SIN, CA_PHN |
| **POPIA** (South Africa) | ZA_ID |

---

## Implementation Notes

### Pattern Confidence Levels

- **Checksum-validated match**: 0.95-0.99
- **Format match with context**: 0.85-0.94
- **Format match only**: 0.70-0.84
- **Partial/uncertain match**: 0.50-0.69

### False Positive Mitigation

Many international IDs are numeric sequences that could match other data:

1. **Context keywords**: Look for labels like "CPF:", "NRIC:", "身份证号"
2. **Length validation**: Enforce exact digit counts
3. **Checksum validation**: Apply when algorithm is known
4. **Character constraints**: Enforce letter/digit positions

### Character Set Considerations

Some identifiers may appear in:
- **Native script**: 身份证号码, 주민등록번호
- **Romanized form**: Simplified labels in English
- **Mixed**: Numbers universal, labels localized

Detection should handle both where applicable.

---

## Sources

- [National identification number - Wikipedia](https://en.wikipedia.org/wiki/National_identification_number)
- [OECD Tax Identification Numbers Portal](https://www.oecd.org/en/networks/global-forum-tax-transparency/resources/aeoi-implementation-portal/tax-identification-numbers.html)
- [Microsoft Purview Sensitive Information Types](https://learn.microsoft.com/en-us/purview/sensitive-information-type-entity-definitions)
- [NHS Number Specification](https://www.england.nhs.uk/long-read/the-nhs-number/)
- [Services Australia - Healthcare Identifiers](https://www.servicesaustralia.gov.au/individual-healthcare-identifiers)
- Country-specific government sources

---

*This document proposes additions to the OpenRisk Entity Registry. Implementation requires pattern development and validation for each entity type.*
