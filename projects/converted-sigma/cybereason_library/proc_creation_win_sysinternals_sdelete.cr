// Title: Potential File Overwrite Via Sysinternals SDelete
// ID: a4824fca-976f-4964-b334-0621379e84c4
// Status: test
// Level: high
// Author: frack113
// Date: 2021-06-03
// Tags: attack.impact, attack.t1485
// Description: Detects the use of SDelete to erase a file not the free space
// Converted by: Sigma Universal SIEM/EDR CLI

((OriginalFileName == "sdelete.exe") AND NOT (((CommandLine contains " -h" OR CommandLine contains " -c" OR CommandLine contains " -z" OR CommandLine contains " /\\?"))))
