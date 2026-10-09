// Title: Registry Modification for OCI DLL Redirection
// ID: c0e0bdec-3e3d-47aa-9974-05539c999c89
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2026-01-24
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.defense-impairment, attack.t1112, attack.t1574.001
// Description: Detects registry modifications related to 'OracleOciLib' and 'OracleOciLibPath' under 'MSDTC' settings.
// Threat actors may modify these registry keys to redirect the loading of 'oci.dll' to a malicious DLL, facilitating phantom DLL hijacking via the MSDTC service.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject endswith "\\SOFTWARE\\Microsoft\\MSDTC\\MTxOCI\\OracleOciLib") and not ((Details contains "oci.dll"))) or ((TargetObject endswith "\\SOFTWARE\\Microsoft\\MSDTC\\MTxOCI\\OracleOciLibPath") and not ((Details contains "%SystemRoot%\\System32\\"))))
