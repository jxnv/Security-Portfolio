// Title: Execution Of Script Located In Potentially Suspicious Directory
// ID: 30bcce26-51c5-49f2-99c8-7b59e3af36c7
// Status: test
// Level: medium
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2023-06-02
// Tags: attack.execution
// Description: Detects executions of scripts located in potentially suspicious locations such as "/tmp" via a shell such as "bash", "sh", etc.
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains " -c ") AND ((Image="*/bash" OR Image="*/csh" OR Image="*/dash" OR Image="*/fish" OR Image="*/ksh" OR Image="*/sh" OR Image="*/zsh")) AND (CommandLine contains "/tmp/"))
