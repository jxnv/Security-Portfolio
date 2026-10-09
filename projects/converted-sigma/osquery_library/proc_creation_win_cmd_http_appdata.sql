-- Title: Command Line Execution with Suspicious URL and AppData Strings
-- ID: 1ac8666b-046f-4201-8aba-1951aaec03a3
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
-- Date: 2019-01-16
-- Tags: attack.execution, attack.command-and-control, attack.t1059.003, attack.t1059.001, attack.t1105
-- Description: Detects a suspicious command line execution that includes an URL and AppData string in the command line parameters as used by several droppers (js/vbs > powershell)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (Image="*\\cmd.exe" AND (CommandLine LIKE '%http%' AND CommandLine LIKE '%://%' AND CommandLine LIKE '%%AppData%%'))
