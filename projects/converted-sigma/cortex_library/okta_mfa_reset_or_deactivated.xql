// Title: Okta MFA Reset or Deactivated
// ID: 50e068d7-1e6b-4054-87e5-0a592c40c7e0
// Status: test
// Level: medium
// Author: Austin Songer @austinsonger
// Date: 2021-09-21
// Tags: attack.persistence, attack.credential-access, attack.defense-impairment, attack.t1556.006
// Description: Detects when an attempt at deactivating  or resetting MFA.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((eventType = "user.mfa.factor.deactivate" or eventType = "user.mfa.factor.reset_all"))
