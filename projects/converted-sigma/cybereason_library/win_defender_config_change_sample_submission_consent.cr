// Title: Windows Defender Submit Sample Feature Disabled
// ID: 91903aba-1088-42ee-b680-d6d94fe002b0
// Status: stable
// Level: low
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-06
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects disabling of the "Automatic Sample Submission" feature of Windows Defender.
// Converted by: Sigma Universal SIEM/EDR CLI

(EventID == "5007" AND NewValue contains "\\Real-Time Protection\\SubmitSamplesConsent = 0x0")
