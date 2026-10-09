// Title: Python Reverse Shell Execution Via PTY And Socket Modules
// ID: 32e62bc7-3de0-4bb1-90af-532978fe42c0
// Status: test
// Level: high
// Author: @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-24
// Tags: attack.execution
// Description: Detects the execution of python with calls to the socket and pty module in order to connect and spawn a potential reverse shell.
// Converted by: Sigma Universal SIEM/EDR CLI

(Image contains "python" AND (CommandLine contains " -c " AND CommandLine contains "import" AND CommandLine contains "pty" AND CommandLine contains "socket" AND CommandLine contains "spawn" AND CommandLine contains ".connect"))
