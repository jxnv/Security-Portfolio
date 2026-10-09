// Title: Suspicious File Created Via OneNote Application
// ID: fcc6d700-68d9-4241-9a1a-06874d621b06
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-09
// Tags: attack.stealth
// Description: Detects suspicious files created via the OneNote application. This could indicate a potential malicious ".one"/".onepkg" file was executed as seen being used in malware activity in the wild
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\onenote.exe" OR Image="*\\onenotem.exe" OR Image="*\\onenoteim.exe") AND TargetFilename: "*\\AppData\\Local\\Temp\\OneNote\\*" AND (TargetFilename="*.bat" OR TargetFilename="*.chm" OR TargetFilename="*.cmd" OR TargetFilename="*.dll" OR TargetFilename="*.exe" OR TargetFilename="*.hta" OR TargetFilename="*.htm" OR TargetFilename="*.html" OR TargetFilename="*.js" OR TargetFilename="*.lnk" OR TargetFilename="*.ps1" OR TargetFilename="*.vbe" OR TargetFilename="*.vbs" OR TargetFilename="*.wsf"))
