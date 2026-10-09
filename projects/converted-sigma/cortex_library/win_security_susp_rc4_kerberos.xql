// Title: Suspicious Kerberos RC4 Ticket Encryption
// ID: 496a0e47-0a33-4dca-b009-9e6ca3591f39
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2017-02-06
// Tags: attack.credential-access, attack.t1558.003
// Description: Detects service ticket requests using RC4 encryption type
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 4769 and TicketOptions = "0x40810000" and TicketEncryptionType = "0x17") and not ((ServiceName endswith "$")))
