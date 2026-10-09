// Title: Suspicious Unsigned Thor Scanner Execution
// ID: ea5c131b-380d-49f9-aeb3-920694da4d4b
// Status: stable
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-10-29
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
// Description: Detects loading and execution of an unsigned thor scanner binary.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\thor.exe" OR Image="*\\thor64.exe") AND (ImageLoaded="*\\thor.exe" OR ImageLoaded="*\\thor64.exe")) AND NOT ((Signed: "true" AND SignatureStatus: "valid" AND Signature: "Nextron Systems GmbH")))
