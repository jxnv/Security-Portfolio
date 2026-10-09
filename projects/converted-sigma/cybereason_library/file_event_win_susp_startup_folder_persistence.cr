// Title: Suspicious Startup Folder Persistence
// ID: 28208707-fe31-437f-9a7f-4b1108b94d2e
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2022-08-10
// Tags: attack.privilege-escalation, attack.execution, attack.t1204.002, attack.persistence, attack.t1547.001
// Description: Detects the creation of potentially malicious script and executable files in Windows startup folders, which is a common persistence technique used by threat actors.
// These files (.ps1, .vbs, .js, .bat, etc.) are automatically executed when a user logs in, making the Startup folder an attractive target for attackers.
// This technique is frequently observed in malvertising campaigns and malware distribution where attackers attempt to maintain long-term access to compromised systems.
// Converted by: Sigma Universal SIEM/EDR CLI

(TargetFilename contains "\\Windows\\Start Menu\\Programs\\Startup\\" AND (TargetFilename="*.bat" OR TargetFilename="*.cmd" OR TargetFilename="*.dll" OR TargetFilename="*.hta" OR TargetFilename="*.jar" OR TargetFilename="*.js" OR TargetFilename="*.jse" OR TargetFilename="*.msi" OR TargetFilename="*.ps1" OR TargetFilename="*.psd1" OR TargetFilename="*.psm1" OR TargetFilename="*.scr" OR TargetFilename="*.url" OR TargetFilename="*.vba" OR TargetFilename="*.vbe" OR TargetFilename="*.vbs" OR TargetFilename="*.wsf"))
