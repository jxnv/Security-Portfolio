// Title: Windows Update Error
// ID: 13cfeb75-9e33-4d04-b0f7-ab8faaa95a59
// Status: stable
// Level: informational
// Author: frack113
// Date: 2021-12-04
// Tags: attack.impact, attack.resource-development, attack.t1584
// Description: Detects Windows update errors including installation failures and connection issues. Defenders should observe this in case critical update KBs aren't installed.
// Converted by: Sigma Universal SIEM/EDR CLI

(Provider_Name == "Microsoft-Windows-WindowsUpdateClient" AND (EventID == "16" OR EventID == "20" OR EventID == "24" OR EventID == "213" OR EventID == "217"))
