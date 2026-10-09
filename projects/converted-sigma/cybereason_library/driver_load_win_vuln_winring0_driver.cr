// Title: Vulnerable WinRing0 Driver Load
// ID: 1a42dfa6-6cb2-4df9-9b48-295be477e835
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-07-26
// Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
// Description: Detects the load of a signed WinRing0 driver often used by threat actors, crypto miners (XMRIG) or malware for privilege escalation
// Converted by: Sigma Universal SIEM/EDR CLI

((Hashes contains "IMPHASH=D41FA95D4642DC981F10DE36F4DC8CD7") OR ((ImageLoaded="*\\WinRing0x64.sys" OR ImageLoaded="*\\WinRing0.sys" OR ImageLoaded="*\\WinRing0.dll" OR ImageLoaded="*\\WinRing0x64.dll" OR ImageLoaded="*\\winring00x64.sys")))
