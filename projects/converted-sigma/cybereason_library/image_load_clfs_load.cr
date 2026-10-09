// Title: Clfs.SYS Loaded By Process Located In a Potential Suspicious Location
// ID: fb4e2211-6d08-426b-8e6f-0d4a161e3b1d
// Status: experimental
// Level: medium
// Author: X__Junior
// Date: 2025-01-20
// Tags: attack.execution, attack.t1059
// Description: Detects Clfs.sys being loaded by a process running from a potentially suspicious location. Clfs.sys is loaded as part of many CVEs exploits that targets Common Log File.
// Converted by: Sigma Universal SIEM/EDR CLI

((ImageLoaded="*\\clfs.sys") AND (((Image contains ":\\Perflogs\\" OR Image contains ":\\Users\\Public\\" OR Image contains "\\Temporary Internet" OR Image contains "\\Windows\\Temp\\")) OR (((Image contains ":\\Users\\" AND Image contains "\\Favorites\\")) OR ((Image contains ":\\Users\\" AND Image contains "\\Favourites\\")) OR ((Image contains ":\\Users\\" AND Image contains "\\Contacts\\")) OR ((Image contains ":\\Users\\" AND Image contains "\\Pictures\\")))))
