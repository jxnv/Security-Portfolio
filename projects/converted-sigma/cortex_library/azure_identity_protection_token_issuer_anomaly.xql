// Title: SAML Token Issuer Anomaly
// ID: e3393cba-31f0-4207-831e-aef90ab17a8c
// Status: test
// Level: high
// Author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
// Date: 2023-09-03
// Tags: attack.t1606, attack.credential-access
// Description: Indicates the SAML token issuer for the associated SAML token is potentially compromised. The claims included in the token are unusual or match known attacker patterns
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (riskEventType = "tokenIssuerAnomaly")
