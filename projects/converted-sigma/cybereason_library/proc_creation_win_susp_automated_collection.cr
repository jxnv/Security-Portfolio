// Title: Automated Collection Command Prompt
// ID: f576a613-2392-4067-9d1a-9345fb58d8d1
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-07-28
// Tags: attack.collection, attack.t1119, attack.credential-access, attack.t1552.001
// Description: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains ".doc" OR CommandLine contains ".docx" OR CommandLine contains ".xls" OR CommandLine contains ".xlsx" OR CommandLine contains ".ppt" OR CommandLine contains ".pptx" OR CommandLine contains ".rtf" OR CommandLine contains ".pdf" OR CommandLine contains ".txt")) AND (((CommandLine contains "dir " AND CommandLine contains " /b " AND CommandLine contains " /s ")) OR (OriginalFileName == "FINDSTR.EXE" AND (CommandLine contains " /e " OR CommandLine contains " /si "))))
