// Title: Password Protected ZIP File Opened
// ID: 00ba9da1-b510-4f6b-b258-8d338836180f
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-05-09
// Tags: attack.stealth, attack.t1027
// Description: Detects the extraction of password protected ZIP archives. See the filename variable for more details on which file has been opened.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 5379 and TargetName contains "Microsoft_Windows_Shell_ZipFolder:filename") and not ((TargetName contains "\\Temporary Internet Files\\Content.Outlook")))
