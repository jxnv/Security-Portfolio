// Title: Wusa.EXE Executed By Parent Process Located In Suspicious Location
// ID: ef64fc9c-a45e-43cc-8fd8-7d75d73b4c99
// Status: test
// Level: high
// Author: X__Junior (Nextron Systems)
// Date: 2023-11-26
// Tags: attack.execution
// Description: Detects execution of the "wusa.exe" (Windows Update Standalone Installer) utility by a parent process that is located in a suspicious location.
// Attackers could instantiate an instance of "wusa.exe" in order to bypass User Account Control (UAC). They can duplicate the access token from "wusa.exe" to gain elevated privileges.
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\wusa.exe") AND (((ParentImage contains ":\\Perflogs\\" OR ParentImage contains ":\\Users\\Public\\" OR ParentImage contains ":\\Windows\\Temp\\" OR ParentImage contains "\\Appdata\\Local\\Temp\\" OR ParentImage contains "\\Temporary Internet")) OR (((ParentImage contains ":\\Users\\" AND ParentImage contains "\\Favorites\\")) OR ((ParentImage contains ":\\Users\\" AND ParentImage contains "\\Favourites\\")) OR ((ParentImage contains ":\\Users\\" AND ParentImage contains "\\Contacts\\")) OR ((ParentImage contains ":\\Users\\" AND ParentImage contains "\\Pictures\\")))) AND NOT ((CommandLine contains ".msu")))
