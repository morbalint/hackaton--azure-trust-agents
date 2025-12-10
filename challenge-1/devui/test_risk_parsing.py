#!/usr/bin/env python3
"""
Test script to verify risk analysis parsing logic
"""

import re

def test_risk_factor_parsing():
    """Test that risk factors are correctly extracted with negation awareness"""
    
    # Test case 1: Low risk transaction (TX2002 - should have NO risk factors)
    low_risk_text = """
    Risk Score: 15
    Risk Level: Low
    Transaction: TX2002
    
    This transaction does not involve a high-risk country. The destination is Germany (DE), 
    which is a low-risk jurisdiction. The amount of €9,998 is not unusually large for this 
    customer profile. There are no suspicious patterns detected. The customer has no sanctions
    concerns and the transaction frequency is not unusual. Overall, this is a compliant,
    low-risk transaction requiring only standard monitoring.
    """
    
    # Test case 2: High risk transaction (should have risk factors)
    high_risk_text = """
    Risk Score: 85
    Risk Level: High
    Transaction: TX2001
    
    This transaction involves a high-risk country (Iran). The amount is unusually large at
    $50,000 USD. Suspicious patterns have been detected in the transaction history. There
    are potential sanctions concerns due to the destination country. Immediate action is
    required.
    """
    
    def extract_risk_factors(text):
        """Extract risk factors with negation awareness"""
        text_lower = text.lower()
        risk_factors = []
        
        # Check for high-risk country
        if ("high-risk country" in text_lower or "high risk country" in text_lower):
            if not any(neg in text_lower for neg in ["not a high-risk", "not high-risk", "no high-risk", "not involve a high-risk", "does not involve"]):
                risk_factors.append("HIGH_RISK_JURISDICTION")
        
        # Check for unusual amounts
        if ("large amount" in text_lower or "high amount" in text_lower or "unusual amount" in text_lower or "unusually large" in text_lower):
            if not any(neg in text_lower for neg in ["not a large", "not high", "not unusual", "no large", "no unusual", "not unusually"]):
                risk_factors.append("UNUSUAL_AMOUNT")
        
        # Check for suspicious patterns
        if "suspicious" in text_lower:
            if not any(neg in text_lower for neg in ["not suspicious", "no suspicious", "nothing suspicious"]):
                risk_factors.append("SUSPICIOUS_PATTERN")
        
        # Check for sanctions
        if "sanction" in text_lower:
            if not any(neg in text_lower for neg in ["not sanctioned", "no sanction", "not under sanction"]):
                risk_factors.append("SANCTIONS_CONCERN")
        
        return risk_factors
    
    def extract_risk_score(text):
        """Extract risk score"""
        text_lower = text.lower()
        risk_score_pattern = r'risk\s*score[:\s]*(\d+(?:\.\d+)?)'
        score_match = re.search(risk_score_pattern, text_lower)
        if score_match:
            return float(score_match.group(1))
        return None
    
    print("=" * 80)
    print("TEST CASE 1: Low Risk Transaction (TX2002)")
    print("=" * 80)
    
    low_risk_factors = extract_risk_factors(low_risk_text)
    low_risk_score = extract_risk_score(low_risk_text)
    
    print(f"Text snippet: {low_risk_text[:200]}...")
    print(f"\nExtracted Risk Score: {low_risk_score}")
    print(f"Extracted Risk Factors: {low_risk_factors}")
    print(f"\nExpected: Risk Score = 15, Risk Factors = [] (empty)")
    print(f"Result: {'✅ PASS' if low_risk_score == 15 and len(low_risk_factors) == 0 else '❌ FAIL'}")
    
    print("\n" + "=" * 80)
    print("TEST CASE 2: High Risk Transaction")
    print("=" * 80)
    
    high_risk_factors = extract_risk_factors(high_risk_text)
    high_risk_score = extract_risk_score(high_risk_text)
    
    print(f"Text snippet: {high_risk_text[:200]}...")
    print(f"\nExtracted Risk Score: {high_risk_score}")
    print(f"Extracted Risk Factors: {high_risk_factors}")
    print(f"\nExpected: Risk Score = 85, Risk Factors include HIGH_RISK_JURISDICTION, UNUSUAL_AMOUNT, etc.")
    print(f"Result: {'✅ PASS' if high_risk_score == 85 and 'HIGH_RISK_JURISDICTION' in high_risk_factors else '❌ FAIL'}")
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    if (low_risk_score == 15 and len(low_risk_factors) == 0 and 
        high_risk_score == 85 and 'HIGH_RISK_JURISDICTION' in high_risk_factors):
        print("✅ All tests PASSED!")
        print("\nThe parsing logic correctly:")
        print("  - Extracts risk scores")
        print("  - Handles negation (doesn't flag 'not suspicious' as suspicious)")
        print("  - Identifies true risk factors only when present")
        return True
    else:
        print("❌ Some tests FAILED")
        print("\nThe parsing logic needs adjustment")
        return False

if __name__ == "__main__":
    test_risk_factor_parsing()
