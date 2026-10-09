// Title: Access of Sudoers File Content
// ID: 0f79c4d2-4e1f-4683-9c36-b5469a665e06
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-06-20
// Tags: attack.reconnaissance, attack.t1592.004
// Description: Detects the execution of a text-based file access or inspection utilities to read the content of /etc/sudoers in order to potentially list all users that have sudo rights.
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*/cat" OR Image="*/ed" OR Image="*/egrep" OR Image="*/emacs" OR Image="*/fgrep" OR Image="*/grep" OR Image="*/head" OR Image="*/less" OR Image="*/more" OR Image="*/nano" OR Image="*/tail") AND CommandLine contains " /etc/sudoers")
