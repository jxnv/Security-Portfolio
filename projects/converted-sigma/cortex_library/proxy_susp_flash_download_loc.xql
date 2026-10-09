// Title: Flash Player Update from Suspicious Location
// ID: 4922a5dd-6743-4fc2-8e81-144374280997
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2017-10-25
// Tags: attack.initial-access, attack.stealth, attack.t1189, attack.execution, attack.t1204.002, attack.t1036.005
// Description: Detects a flashplayer update from an unofficial location
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((c-uri contains "/flash_install.php") or (c-uri endswith "/install_flash_player.exe")) and not ((cs-host endswith ".adobe.com")))
