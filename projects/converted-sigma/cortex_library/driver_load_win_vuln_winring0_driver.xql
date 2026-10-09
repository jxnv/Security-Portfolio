// Title: Vulnerable WinRing0 Driver Load
// ID: 1a42dfa6-6cb2-4df9-9b48-295be477e835
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-07-26
// Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
// Description: Detects the load of a signed WinRing0 driver often used by threat actors, crypto miners (XMRIG) or malware for privilege escalation
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Hashes contains "IMPHASH=D41FA95D4642DC981F10DE36F4DC8CD7") or ((ImageLoaded endswith "\\WinRing0x64.sys" or ImageLoaded endswith "\\WinRing0.sys" or ImageLoaded endswith "\\WinRing0.dll" or ImageLoaded endswith "\\WinRing0x64.dll" or ImageLoaded endswith "\\winring00x64.sys")))
