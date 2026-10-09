// Title: Potential Ruby Reverse Shell
// ID: b8bdac18-c06e-4016-ac30-221553e74f59
// Status: test
// Level: medium
// Author: @d4ns4n_
// Date: 2023-04-07
// Tags: attack.execution
// Description: Detects execution of ruby with the "-e" flag and calls to "socket" related functions. This could be an indication of a potential attempt to setup a reverse shell
// Converted by: Sigma Universal SIEM/EDR CLI

(Image: "*ruby*" AND (CommandLine: "* -e*" AND CommandLine: "*rsocket*" AND CommandLine: "*TCPSocket*") AND (CommandLine: "* ash*" OR CommandLine: "* bash*" OR CommandLine: "* bsh*" OR CommandLine: "* csh*" OR CommandLine: "* ksh*" OR CommandLine: "* pdksh*" OR CommandLine: "* sh*" OR CommandLine: "* tcsh*"))
