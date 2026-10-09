// Title: PUA - Ngrok Execution
// ID: ee37eb7c-a4e7-4cd5-8fa4-efa27f1c3f31
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-05-14
// Tags: attack.command-and-control, attack.t1572
// Description: Detects the use of Ngrok, a utility used for port forwarding and tunneling, often used by threat actors to make local protected services publicly available.
// Involved domains are bin.equinox.io for download and *.ngrok.io for connections.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains " tcp 139" OR CommandLine contains " tcp 445" OR CommandLine contains " tcp 3389" OR CommandLine contains " tcp 5985" OR CommandLine contains " tcp 5986")) OR ((CommandLine contains " start " AND CommandLine contains "--all" AND CommandLine contains "--config" AND CommandLine contains ".yml")) OR (Image="*ngrok.exe" AND (CommandLine contains " tcp " OR CommandLine contains " http " OR CommandLine contains " authtoken ")) OR ((CommandLine contains ".exe authtoken " OR CommandLine contains ".exe start --all")))
