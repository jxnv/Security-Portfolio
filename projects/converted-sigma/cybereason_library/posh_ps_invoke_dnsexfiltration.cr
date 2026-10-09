// Title: Powershell DNSExfiltration
// ID: d59d7842-9a21-4bc6-ba98-64bfe0091355
// Status: test
// Level: high
// Author: frack113
// Date: 2022-01-07
// Tags: attack.exfiltration, attack.t1048
// Description: DNSExfiltrator allows for transferring (exfiltrate) a file over a DNS request covert channel
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText contains "Invoke-DNSExfiltrator") OR ((ScriptBlockText contains " -i " AND ScriptBlockText contains " -d " AND ScriptBlockText contains " -p " AND ScriptBlockText contains " -doh " AND ScriptBlockText contains " -t ")))
