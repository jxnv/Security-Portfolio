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

(((CommandLine: "*:!/*" OR CommandLine: "*:!$*" OR CommandLine: "*:!..*" OR CommandLine: "*:lua *" OR CommandLine: "*:py *" OR CommandLine: "*:shell*" OR CommandLine: "*/bin/bash*" OR CommandLine: "*/bin/dash*" OR CommandLine: "*/bin/fish*" OR CommandLine: "*/bin/sh*" OR CommandLine: "*/bin/csh*" OR CommandLine: "*/bin/ksh*" OR CommandLine: "*/bin/zsh*" OR CommandLine: "*/bin/tmux*")) AND ((Image="*/rvim" OR Image="*/vi" OR Image="*/vim" OR Image="*/vimdiff") AND (CommandLine: "* --cmd *" OR CommandLine: "* -c*")))
