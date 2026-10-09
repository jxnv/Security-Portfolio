// Title: Potential Ruby Reverse Shell
// ID: b8bdac18-c06e-4016-ac30-221553e74f59
// Status: test
// Level: medium
// Author: @d4ns4n_
// Date: 2023-04-07
// Tags: attack.execution
// Description: Detects execution of ruby with the "-e" flag and calls to "socket" related functions. This could be an indication of a potential attempt to setup a reverse shell
// Converted by: Sigma Universal SIEM/EDR CLI

(Image contains "ruby" AND (CommandLine contains " -e" AND CommandLine contains "rsocket" AND CommandLine contains "TCPSocket") AND (CommandLine contains " ash" OR CommandLine contains " bash" OR CommandLine contains " bsh" OR CommandLine contains " csh" OR CommandLine contains " ksh" OR CommandLine contains " pdksh" OR CommandLine contains " sh" OR CommandLine contains " tcsh"))
