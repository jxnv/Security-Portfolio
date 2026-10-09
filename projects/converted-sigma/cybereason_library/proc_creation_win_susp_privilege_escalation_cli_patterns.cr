// Title: Suspicious RunAs-Like Flag Combination
// ID: 50d66fb0-03f8-4da0-8add-84e77d12a020
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-11-11
// Tags: attack.privilege-escalation
// Description: Detects suspicious command line flags that let the user set a target user and command as e.g. seen in PsExec-like tools
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains " -c cmd" OR CommandLine contains " -c \"cmd" OR CommandLine contains " -c powershell" OR CommandLine contains " -c \"powershell" OR CommandLine contains " --command cmd" OR CommandLine contains " --command powershell" OR CommandLine contains " -c whoami" OR CommandLine contains " -c wscript" OR CommandLine contains " -c cscript")) AND ((CommandLine contains " -u system " OR CommandLine contains " --user system " OR CommandLine contains " -u NT" OR CommandLine contains " -u \"NT" OR CommandLine contains " -u 'NT" OR CommandLine contains " --system " OR CommandLine contains " -u administrator ")))
