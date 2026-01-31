//! Validation functions for detected entities
//!
//! Fast implementations of common validation algorithms.

/// Validate credit card number using Luhn algorithm
pub fn luhn(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    // Credit cards are 13-19 digits
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();

    sum % 10 == 0
}

/// Validate SSN format (basic format check, not context)
pub fn ssn_format(ssn: &str) -> bool {
    let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() != 9 {
        return false;
    }

    // Parse area, group, serial
    let area: u32 = match digits[0..3].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let group: u32 = match digits[3..5].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let serial: u32 = match digits[5..9].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    // Invalid areas: 000, 666, 900-999
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }

    // Group and serial can't be 0
    group > 0 && serial > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_valid() {
        // Valid test card numbers
        assert!(luhn("4111111111111111")); // Visa test
        assert!(luhn("5500000000000004")); // Mastercard test
        assert!(luhn("4111-1111-1111-1111")); // With dashes
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!luhn("4111111111111112")); // Wrong check digit
        assert!(!luhn("1234567890")); // Too short
        assert!(!luhn("abcd")); // Not numbers
    }

    #[test]
    fn test_ssn_valid() {
        assert!(ssn_format("123-45-6789"));
        assert!(ssn_format("123456789"));
    }

    #[test]
    fn test_ssn_invalid() {
        assert!(!ssn_format("000-45-6789")); // Invalid area
        assert!(!ssn_format("666-45-6789")); // Invalid area
        assert!(!ssn_format("900-45-6789")); // Invalid area
        assert!(!ssn_format("123-00-6789")); // Invalid group
        assert!(!ssn_format("123-45-0000")); // Invalid serial
        assert!(!ssn_format("12345678")); // Too short
    }
}
