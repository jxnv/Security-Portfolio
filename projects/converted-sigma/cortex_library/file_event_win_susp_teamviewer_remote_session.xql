// Title: TeamViewer Remote Session
// ID: 162ab1e4-6874-4564-853c-53ec3ab8be01
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-01-30
// Tags: attack.command-and-control, attack.t1219.002
// Description: Detects the creation of log files during a TeamViewer remote session
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path endswith "\\TeamViewer\\RemotePrinting\\tvprint.db" or action_file_path endswith "\\TeamViewer\\TVNetwork.log")) or ((action_file_path contains "\\TeamViewer" and action_file_path contains "_Logfile.log")))
