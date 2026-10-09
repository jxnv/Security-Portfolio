// Title: MacOS Emond Launch Daemon
// ID: 23c43900-e732-45a4-8354-63e4a6c187ce
// Status: test
// Level: medium
// Author: Alejandro Ortuno, oscd.community
// Date: 2020-10-23
// Tags: attack.persistence, attack.privilege-escalation, attack.t1546.014
// Description: Detects additions to the Emond Launch Daemon that adversaries may use to gain persistence and elevate privileges.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path contains "/etc/emond.d/rules/" and action_file_path endswith ".plist") or (action_file_path contains "/private/var/db/emondClients/"))
