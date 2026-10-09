// Title: Sysmon Configuration Error
// ID: 815cd91b-7dbc-4247-841a-d7dd1392b0a8
// Status: test
// Level: high
// Author: frack113
// Date: 2021-06-04
// Tags: attack.stealth, attack.t1564
// Description: Detects when an adversary is trying to hide it's action from Sysmon logging based on error messages
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((Description contains "Failed to open service configuration with error" or Description contains "Failed to connect to the driver to update configuration")) and not ((((Description contains "Failed to open service configuration with error 19" or Description contains "Failed to open service configuration with error 93")) or ((Description contains "Failed to open service configuration with error" and Description contains "Last error: The media is write protected.")) or ((Description contains "Failed to open service configuration with error" and Description contains "Last error: Média protégé en écriture.")))))
