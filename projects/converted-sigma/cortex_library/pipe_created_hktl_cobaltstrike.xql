// Title: CobaltStrike Named Pipe
// ID: d5601f8c-b26f-4ab0-9035-69e11a8d4ad2
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems), Wojciech Lesicki
// Date: 2021-05-25
// Tags: attack.privilege-escalation, attack.stealth, attack.t1055
// Description: Detects the creation of a named pipe as used by CobaltStrike
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((PipeName contains "\\MSSE-" and PipeName contains "-server")) or (PipeName startswith "\\interprocess_") or (PipeName startswith "\\lsarpc_") or (PipeName startswith "\\mojo_") or (PipeName startswith "\\msagent_") or (PipeName startswith "\\netlogon_") or (PipeName startswith "\\postex_") or (PipeName startswith "\\samr_") or (PipeName startswith "\\srvsvc_") or (PipeName startswith "\\status_") or (PipeName startswith "\\wkssvc_"))
