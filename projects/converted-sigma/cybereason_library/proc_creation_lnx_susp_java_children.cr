// Title: Suspicious Java Children Processes
// ID: d292e0af-9a18-420c-9525-ec0ac3936892
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-03
// Tags: attack.execution, attack.t1059
// Description: Detects java process spawning suspicious children
// Converted by: Sigma Universal SIEM/EDR CLI

(ParentImage="*/java" AND (CommandLine contains "/bin/sh" OR CommandLine contains "bash" OR CommandLine contains "dash" OR CommandLine contains "ksh" OR CommandLine contains "zsh" OR CommandLine contains "csh" OR CommandLine contains "fish" OR CommandLine contains "curl" OR CommandLine contains "wget" OR CommandLine contains "python"))
