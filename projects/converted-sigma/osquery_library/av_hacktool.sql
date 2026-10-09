-- Title: Antivirus - Hacktool Signature
-- ID: fa0c05b6-8ad3-468d-8231-c1cbccb64fba
-- Status: stable
-- Level: high
-- Author: Florian Roth (Nextron Systems), Arnim Rupp
-- Date: 2021-08-16
-- Tags: attack.execution, attack.t1204
-- Description: Detects a highly relevant Antivirus alert that reports a hack tool or other attack tool.
-- This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((Signature="ATK/*" OR Signature="Exploit.Script.CVE*" OR Signature="HKTL*" OR Signature="HTOOL*" OR Signature="PWS.*" OR Signature="PWSX*" OR Signature="SecurityTool*")) OR ((Signature LIKE '%Adfind%' OR Signature LIKE '%BloodH%' OR Signature LIKE '%BloodyAD%' OR Signature LIKE '%Brutel%' OR Signature LIKE '%BruteR%' OR Signature LIKE '%Cobalt%' OR Signature LIKE '%COBEACON%' OR Signature LIKE '%Cometer%' OR Signature LIKE '%DumpCreds%' OR Signature LIKE '%EDRfreeze%' OR Signature LIKE '%FastReverseProxy%' OR Signature LIKE '%Hacktool%' OR Signature LIKE '%Havoc%' OR Signature LIKE '%Impacket%' OR Signature LIKE '%Keylogger%' OR Signature LIKE '%Koadic%' OR Signature LIKE '%Mimikatz%' OR Signature LIKE '%Nighthawk%' OR Signature LIKE '%PentestPowerShell%' OR Signature LIKE '%Potato%' OR Signature LIKE '%PowerSploit%' OR Signature LIKE '%PowerSSH%' OR Signature LIKE '%PshlSpy%' OR Signature LIKE '%PSWTool%' OR Signature LIKE '%PWCrack%' OR Signature LIKE '%PWDump%' OR Signature LIKE '%Responder%' OR Signature LIKE '%Rozena%' OR Signature LIKE '%Rusthound%' OR Signature LIKE '%Sbelt%' OR Signature LIKE '%Seatbelt%' OR Signature LIKE '%SecurityTool%' OR Signature LIKE '%SharpDump%' OR Signature LIKE '%SharpHound%' OR Signature LIKE '%Shellcode%' OR Signature LIKE '%Sliver%' OR Signature LIKE '%Snaffler%' OR Signature LIKE '%SOAPHound%' OR Signature LIKE '%Splinter%' OR Signature LIKE '%Stowaway%' OR Signature LIKE '%Swrort%' OR Signature LIKE '%Trojan.Hound%' OR Signature LIKE '%TurtleLoader%' OR Signature LIKE '%Undefend%' OR Signature LIKE '%Undfnd%')))
