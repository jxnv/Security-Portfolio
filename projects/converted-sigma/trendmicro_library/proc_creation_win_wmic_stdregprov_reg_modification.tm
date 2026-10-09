// Title: Registry Manipulation via WMI Stdregprov
// ID: c453ab7a-1f5c-4716-a3b4-dea8135fb43a
// Status: experimental
// Level: medium
// Author: Daniel Koifman (KoifSec)
// Date: 2025-07-30
// Tags: attack.execution, attack.t1047, attack.persistence, attack.defense-impairment, attack.t1112
// Description: Detects the usage of wmic.exe to modify Windows registry via the WMI StdRegProv class write methods (CreateKey, DeleteKey, SetStringValue, etc.).
// This behaviour could be potentially suspicious because it uses an alternative method to modify registry keys instead of legitimate registry tools like reg.exe or regedit.exe.
// Attackers specifically choose this technique to evade detection and bypass security monitoring focused on traditional registry modification commands.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*stdregprov*" AND CommandLine: "*call*") AND (CommandLine: "*CreateKey*" OR CommandLine: "*DeleteKey*" OR CommandLine: "*DeleteValue*" OR CommandLine: "*SetBinaryValue*" OR CommandLine: "*SetDWORDValue*" OR CommandLine: "*SetExpandedStringValue*" OR CommandLine: "*SetMultiStringValue*" OR CommandLine: "*SetQWORDValue*" OR CommandLine: "*SetSecurityDescriptor*" OR CommandLine: "*SetStringValue*")) AND ((Image="*\\wmic.exe") OR (OriginalFileName: "wmic.exe")))
