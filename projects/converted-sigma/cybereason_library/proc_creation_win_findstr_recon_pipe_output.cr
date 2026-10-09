// Title: Recon Command Output Piped To Findstr.EXE
// ID: ccb5742c-c248-4982-8c5c-5571b9275ad3
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems), frack113
// Date: 2023-07-06
// Tags: attack.discovery, attack.t1057
// Description: Detects the execution of a potential recon command where the results are piped to "findstr". This is meant to trigger on inline calls of "cmd.exe" via the "/c" or "/k" for example.
// Attackers often time use this technique to extract specific information they require in their reconnaissance phase.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "ipconfig*|*find" OR CommandLine contains "net*|*find" OR CommandLine contains "netstat*|*find" OR CommandLine contains "ping*|*find" OR CommandLine contains "systeminfo*|*find" OR CommandLine contains "tasklist*|*find" OR CommandLine contains "whoami*|*find")) AND NOT (((CommandLine contains "cmd.exe /c TASKLIST /V |" AND CommandLine contains "FIND /I" AND CommandLine contains "\\xampp\\" AND CommandLine contains "\\catalina_start.bat"))))
