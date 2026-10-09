// Title: Potential PHP Reverse Shell
// ID: c6714a24-d7d5-4283-a36b-3ffd091d5f7e
// Status: test
// Level: high
// Author: @d4ns4n_
// Date: 2023-04-07
// Tags: attack.execution
// Description: Detects usage of the PHP CLI with the "-r" flag which allows it to run inline PHP code. The rule looks for calls to the "fsockopen" function which allows the creation of sockets.
// Attackers often leverage this in combination with functions such as "exec" or "fopen" to initiate a reverse shell connection.
// Converted by: Sigma Universal SIEM/EDR CLI

(Image contains "/php" AND (CommandLine contains " -r " AND CommandLine contains "fsockopen") AND (CommandLine contains "ash" OR CommandLine contains "bash" OR CommandLine contains "bsh" OR CommandLine contains "csh" OR CommandLine contains "ksh" OR CommandLine contains "pdksh" OR CommandLine contains "sh" OR CommandLine contains "tcsh" OR CommandLine contains "zsh"))
