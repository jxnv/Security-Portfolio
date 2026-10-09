// Title: Potential CommandLine Obfuscation Using Unicode Characters From Suspicious Image
// ID: 584bca0f-3608-4402-80fd-4075ff6072e3
// Status: test
// Level: high
// Author: frack113, Florian Roth (Nextron Systems), Josh Nickels
// Date: 2024-09-02
// Tags: attack.stealth, attack.t1027
// Description: Detects potential commandline obfuscation using unicode characters.
// Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\powershell.exe" OR Image="*\\powershell_ise.exe" OR Image="*\\pwsh.exe" OR Image="*\\wscript.exe") AND (OriginalFileName: "Cmd.EXE" OR OriginalFileName: "cscript.exe" OR OriginalFileName: "PowerShell.EXE" OR OriginalFileName: "PowerShell_ISE.EXE" OR OriginalFileName: "pwsh.dll" OR OriginalFileName: "wscript.exe")) AND ((CommandLine: "*ˣ*" OR CommandLine: "*˪*" OR CommandLine: "*ˢ*" OR CommandLine: "*∕*" OR CommandLine: "*⁄*" OR CommandLine: "*―*" OR CommandLine: "*—*" OR CommandLine: "* *" OR CommandLine: "*¯*" OR CommandLine: "*®*" OR CommandLine: "*¶*" OR CommandLine: "*⠀*")))
