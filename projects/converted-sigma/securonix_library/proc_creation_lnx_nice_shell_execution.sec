// Title: Shell Execution via Nice - Linux
// ID: 093d68c7-762a-42f4-9f46-95e79142571a
// Status: test
// Level: high
// Author: Li Ling, Andy Parkidomo, Robert Rakowski, Blake Hartstein (Bloomberg L.P.)
// Date: 2024-09-02
// Tags: attack.discovery, attack.t1083
// Description: Detects the use of the "nice" utility to execute a shell. Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
// Converted by: Sigma Universal SIEM/EDR CLI

(Image="*/nice" AND (CommandLine="*/bin/bash" OR CommandLine="*/bin/dash" OR CommandLine="*/bin/fish" OR CommandLine="*/bin/sh" OR CommandLine="*/bin/zsh"))
