// Title: Antivirus - Hacktool Signature
// ID: fa0c05b6-8ad3-468d-8231-c1cbccb64fba
// Status: stable
// Level: high
// Author: Florian Roth (Nextron Systems), Arnim Rupp
// Date: 2021-08-16
// Tags: attack.execution, attack.t1204
// Description: Detects a highly relevant Antivirus alert that reports a hack tool or other attack tool.
// This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Signature="ATK/*" OR Signature="Exploit.Script.CVE*" OR Signature="HKTL*" OR Signature="HTOOL*" OR Signature="PWS.*" OR Signature="PWSX*" OR Signature="SecurityTool*")) OR ((Signature contains "Adfind" OR Signature contains "BloodH" OR Signature contains "BloodyAD" OR Signature contains "Brutel" OR Signature contains "BruteR" OR Signature contains "Cobalt" OR Signature contains "COBEACON" OR Signature contains "Cometer" OR Signature contains "DumpCreds" OR Signature contains "EDRfreeze" OR Signature contains "FastReverseProxy" OR Signature contains "Hacktool" OR Signature contains "Havoc" OR Signature contains "Impacket" OR Signature contains "Keylogger" OR Signature contains "Koadic" OR Signature contains "Mimikatz" OR Signature contains "Nighthawk" OR Signature contains "PentestPowerShell" OR Signature contains "Potato" OR Signature contains "PowerSploit" OR Signature contains "PowerSSH" OR Signature contains "PshlSpy" OR Signature contains "PSWTool" OR Signature contains "PWCrack" OR Signature contains "PWDump" OR Signature contains "Responder" OR Signature contains "Rozena" OR Signature contains "Rusthound" OR Signature contains "Sbelt" OR Signature contains "Seatbelt" OR Signature contains "SecurityTool" OR Signature contains "SharpDump" OR Signature contains "SharpHound" OR Signature contains "Shellcode" OR Signature contains "Sliver" OR Signature contains "Snaffler" OR Signature contains "SOAPHound" OR Signature contains "Splinter" OR Signature contains "Stowaway" OR Signature contains "Swrort" OR Signature contains "Trojan.Hound" OR Signature contains "TurtleLoader" OR Signature contains "Undefend" OR Signature contains "Undfnd")))
