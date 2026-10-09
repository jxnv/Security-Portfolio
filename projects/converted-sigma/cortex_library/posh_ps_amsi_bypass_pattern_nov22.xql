// Title: AMSI Bypass Pattern Assembly GetType
// ID: e0d6c087-2d1c-47fd-8799-3904103c5a98
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-11-09
// Tags: attack.defense-impairment, attack.t1685, attack.execution
// Description: Detects code fragments found in small and obfuscated AMSI bypass PowerShell scripts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "[Ref].Assembly.GetType" and ScriptBlockText contains "SetValue($null,$true)" and ScriptBlockText contains "NonPublic,Static"))
