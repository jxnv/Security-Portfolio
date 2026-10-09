// Title: AWS Successful Console Login Without MFA
// ID: 77caf516-34e5-4df9-b4db-20744fea0a60
// Status: experimental
// Level: medium
// Author: Thuya@Hacktilizer, Ivan Saakov
// Date: 2025-10-18
// Tags: attack.initial-access, attack.persistence, attack.privilege-escalation, attack.stealth, attack.t1078.004
// Description: Detects successful AWS console logins that were performed without Multi-Factor Authentication (MFA).
// This alert can be used to identify potential unauthorized access attempts, as logging in without MFA can indicate compromised credentials or misconfigured security settings.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (eventName = "ConsoleLogin" and additionalEventData.MFAUsed = "NO" and responseElements.ConsoleLogin = "Success")
