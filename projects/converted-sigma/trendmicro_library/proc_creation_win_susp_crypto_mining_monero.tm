// Title: Potential Crypto Mining Activity
// ID: 66c3b204-9f88-4d0a-a7f7-8a57d521ca55
// Status: stable
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-10-26
// Tags: attack.impact, attack.t1496
// Description: Detects command line parameters or strings often used by crypto miners
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "* --cpu-priority=*" OR CommandLine: "*--donate-level=0*" OR CommandLine: "* -o pool.*" OR CommandLine: "* --nicehash*" OR CommandLine: "* --algo=rx/0 *" OR CommandLine: "*stratum+tcp://*" OR CommandLine: "*stratum+udp://*" OR CommandLine: "*LS1kb25hdGUtbGV2ZWw9*" OR CommandLine: "*0tZG9uYXRlLWxldmVsP*" OR CommandLine: "*tLWRvbmF0ZS1sZXZlbD*" OR CommandLine: "*c3RyYXR1bSt0Y3A6Ly*" OR CommandLine: "*N0cmF0dW0rdGNwOi8v*" OR CommandLine: "*zdHJhdHVtK3RjcDovL*" OR CommandLine: "*c3RyYXR1bSt1ZHA6Ly*" OR CommandLine: "*N0cmF0dW0rdWRwOi8v*" OR CommandLine: "*zdHJhdHVtK3VkcDovL*")) AND NOT (((CommandLine: "* pool.c *" OR CommandLine: "* pool.o *" OR CommandLine: "*gcc -*"))))
