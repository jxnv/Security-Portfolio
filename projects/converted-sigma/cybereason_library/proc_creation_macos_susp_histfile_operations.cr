// Title: Suspicious History File Operations
// ID: 508a9374-ad52-4789-b568-fc358def2c65
// Status: test
// Level: medium
// Author: Mikhail Larin, oscd.community
// Date: 2020-10-17
// Tags: attack.credential-access, attack.t1552.003
// Description: Detects commandline operations on shell history files
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains ".bash_history" OR CommandLine contains ".zsh_history" OR CommandLine contains ".zhistory" OR CommandLine contains ".history" OR CommandLine contains ".sh_history" OR CommandLine contains "fish_history"))
