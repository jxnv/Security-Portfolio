// Title: Raw Paste Service Access
// ID: 5468045b-4fcc-4d1a-973c-c9c9578edacb
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2019-12-05
// Tags: attack.command-and-control, attack.t1071.001, attack.t1102.001, attack.t1102.003
// Description: Detects direct access to raw pastes in different paste services often used by malware in their second stages to download malicious code in encrypted or encoded form
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((c-uri contains ".paste.ee/r/" or c-uri contains ".pastebin.com/raw/" or c-uri contains ".hastebin.com/raw/" or c-uri contains ".ghostbin.co/paste/*/raw/" or c-uri contains "pastetext.net/" or c-uri contains "pastebin.pl/" or c-uri contains "paste.ee/"))
