// Title: Suspicious RunAs-Like Flag Combination
// ID: 50d66fb0-03f8-4da0-8add-84e77d12a020
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-11-11
// Tags: attack.privilege-escalation
// Description: Detects suspicious command line flags that let the user set a target user and command as e.g. seen in PsExec-like tools
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "* -c cmd*" OR CommandLine: "* -c \"cmd*" OR CommandLine: "* -c powershell*" OR CommandLine: "* -c \"powershell*" OR CommandLine: "* --command cmd*" OR CommandLine: "* --command powershell*" OR CommandLine: "* -c whoami*" OR CommandLine: "* -c wscript*" OR CommandLine: "* -c cscript*")) AND ((CommandLine: "* -u system *" OR CommandLine: "* --user system *" OR CommandLine: "* -u NT*" OR CommandLine: "* -u \"NT*" OR CommandLine: "* -u 'NT*" OR CommandLine: "* --system *" OR CommandLine: "* -u administrator *")))
