// Title: Potential Crypto Mining Activity
// ID: 66c3b204-9f88-4d0a-a7f7-8a57d521ca55
// Status: stable
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-10-26
// Tags: attack.impact, attack.t1496
// Description: Detects command line parameters or strings often used by crypto miners
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains " --cpu-priority=" OR CommandLine contains "--donate-level=0" OR CommandLine contains " -o pool." OR CommandLine contains " --nicehash" OR CommandLine contains " --algo=rx/0 " OR CommandLine contains "stratum+tcp://" OR CommandLine contains "stratum+udp://" OR CommandLine contains "LS1kb25hdGUtbGV2ZWw9" OR CommandLine contains "0tZG9uYXRlLWxldmVsP" OR CommandLine contains "tLWRvbmF0ZS1sZXZlbD" OR CommandLine contains "c3RyYXR1bSt0Y3A6Ly" OR CommandLine contains "N0cmF0dW0rdGNwOi8v" OR CommandLine contains "zdHJhdHVtK3RjcDovL" OR CommandLine contains "c3RyYXR1bSt1ZHA6Ly" OR CommandLine contains "N0cmF0dW0rdWRwOi8v" OR CommandLine contains "zdHJhdHVtK3VkcDovL")) AND NOT (((CommandLine contains " pool.c " OR CommandLine contains " pool.o " OR CommandLine contains "gcc -"))))
