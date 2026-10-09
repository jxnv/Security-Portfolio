// Title: Cloudflared Tunnel Execution
// ID: 9a019ffc-3580-4c9d-8d87-079f7e8d3fd4
// Status: test
// Level: medium
// Author: Janantha Marasinghe, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-17
// Tags: attack.command-and-control, attack.t1102, attack.t1090, attack.t1572
// Description: Detects execution of the "cloudflared" tool to connect back to a tunnel. This was seen used by threat actors to maintain persistence and remote access to compromised networks.
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains " tunnel " AND CommandLine contains " run ") AND (CommandLine contains "-config " OR CommandLine contains "-credentials-contents " OR CommandLine contains "-credentials-file " OR CommandLine contains "-token "))
