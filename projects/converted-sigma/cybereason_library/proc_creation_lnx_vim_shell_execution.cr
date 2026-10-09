// Title: Vim GTFOBin Abuse - Linux
// ID: 7ab8f73a-fcff-428b-84aa-6a5ff7877dea
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), Luc Génaux
// Date: 2022-12-28
// Tags: attack.execution, attack.discovery, attack.t1059, attack.t1083
// Description: Detects the use of "vim" and it's siblings commands to execute a shell or proxy commands.
// Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains ":!/" OR CommandLine contains ":!$" OR CommandLine contains ":!.." OR CommandLine contains ":lua " OR CommandLine contains ":py " OR CommandLine contains ":shell" OR CommandLine contains "/bin/bash" OR CommandLine contains "/bin/dash" OR CommandLine contains "/bin/fish" OR CommandLine contains "/bin/sh" OR CommandLine contains "/bin/csh" OR CommandLine contains "/bin/ksh" OR CommandLine contains "/bin/zsh" OR CommandLine contains "/bin/tmux")) AND ((Image="*/rvim" OR Image="*/vi" OR Image="*/vim" OR Image="*/vimdiff") AND (CommandLine contains " --cmd " OR CommandLine contains " -c")))
