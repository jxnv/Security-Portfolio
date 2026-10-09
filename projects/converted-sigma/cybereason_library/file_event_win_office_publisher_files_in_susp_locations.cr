// Title: Publisher Attachment File Dropped In Suspicious Location
// ID: 3d2a2d59-929c-4b78-8c1a-145dfe9e07b1
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-02-08
// Tags: attack.stealth
// Description: Detects creation of files with the ".pub" extension in suspicious or uncommon locations. This could be a sign of attackers abusing Publisher documents
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetFilename contains "\\AppData\\Local\\Temp\\" OR TargetFilename contains "\\Users\\Public\\" OR TargetFilename contains "\\Windows\\Temp\\" OR TargetFilename contains "C:\\Temp\\") AND TargetFilename="*.pub")
