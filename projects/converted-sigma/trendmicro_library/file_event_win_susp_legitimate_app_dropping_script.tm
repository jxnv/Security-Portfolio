// Title: Legitimate Application Dropped Script
// ID: 7d604714-e071-49ff-8726-edeb95a70679
// Status: test
// Level: high
// Author: frack113, Florian Roth (Nextron Systems)
// Date: 2022-08-21
// Tags: attack.stealth, attack.t1218
// Description: Detects LOLBINs and applications that should not legitimately drop script files to disk.
// This may indicate malware staging or abuse of a trusted binary for script-based code execution.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\eqnedt32.exe" OR Image="*\\wordpad.exe" OR Image="*\\wordview.exe" OR Image="*\\certutil.exe" OR Image="*\\certoc.exe" OR Image="*\\CertReq.exe" OR Image="*\\Desktopimgdownldr.exe" OR Image="*\\esentutl.exe" OR Image="*\\mshta.exe" OR Image="*\\AcroRd32.exe" OR Image="*\\RdrCEF.exe" OR Image="*\\hh.exe" OR Image="*\\finger.exe") AND (TargetFilename="*.bat" OR TargetFilename="*.chm" OR TargetFilename="*.csproj" OR TargetFilename="*.hta" OR TargetFilename="*.js" OR TargetFilename="*.jse" OR TargetFilename="*.proj" OR TargetFilename="*.ps1" OR TargetFilename="*.py" OR TargetFilename="*.scf" OR TargetFilename="*.vbe" OR TargetFilename="*.vbs" OR TargetFilename="*.wsf" OR TargetFilename="*.wsh")) AND NOT ((Image="*\\mshta.exe" AND TargetFilename="*.hta")))
