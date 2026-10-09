// Title: Windows Defender Threat Severity Default Action Modified
// ID: 5a9e1b2c-8f7d-4a1e-9b3c-0f6d7e5a4b1f
// Status: experimental
// Level: high
// Author: Matt Anderson (Huntress)
// Date: 2025-07-11
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects modifications or creations of Windows Defender's default threat action settings based on severity to 'allow' or take 'no action'.
// This is a highly suspicious configuration change that effectively disables Defender's ability to automatically mitigate threats of a certain severity level,
// allowing malicious software to run unimpeded. An attacker might use this technique to bypass defenses before executing payloads.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (TargetObject contains "\\Microsoft\\Windows Defender\\Threats\\ThreatSeverityDefaultAction\\" and (TargetObject endswith "\\1" or TargetObject endswith "\\2" or TargetObject endswith "\\4" or TargetObject endswith "\\5") and (Details = "DWORD (0x00000006)" or Details = "DWORD (0x00000009)"))
