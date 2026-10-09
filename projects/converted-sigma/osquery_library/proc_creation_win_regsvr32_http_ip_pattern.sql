-- Title: Potentially Suspicious Regsvr32 HTTP IP Pattern
-- ID: 2dd2c217-bf68-437a-b57c-fe9fd01d5de8
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-01-11
-- Tags: attack.stealth, attack.t1218.010
-- Description: Detects regsvr32 execution to download and install DLLs located remotely where the address is an IP address.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\regsvr32.exe") OR (OriginalFileName = 'REGSVR32.EXE')) AND ((CommandLine LIKE '% /i:http://1%' OR CommandLine LIKE '% /i:http://2%' OR CommandLine LIKE '% /i:http://3%' OR CommandLine LIKE '% /i:http://4%' OR CommandLine LIKE '% /i:http://5%' OR CommandLine LIKE '% /i:http://6%' OR CommandLine LIKE '% /i:http://7%' OR CommandLine LIKE '% /i:http://8%' OR CommandLine LIKE '% /i:http://9%' OR CommandLine LIKE '% /i:https://1%' OR CommandLine LIKE '% /i:https://2%' OR CommandLine LIKE '% /i:https://3%' OR CommandLine LIKE '% /i:https://4%' OR CommandLine LIKE '% /i:https://5%' OR CommandLine LIKE '% /i:https://6%' OR CommandLine LIKE '% /i:https://7%' OR CommandLine LIKE '% /i:https://8%' OR CommandLine LIKE '% /i:https://9%' OR CommandLine LIKE '% -i:http://1%' OR CommandLine LIKE '% -i:http://2%' OR CommandLine LIKE '% -i:http://3%' OR CommandLine LIKE '% -i:http://4%' OR CommandLine LIKE '% -i:http://5%' OR CommandLine LIKE '% -i:http://6%' OR CommandLine LIKE '% -i:http://7%' OR CommandLine LIKE '% -i:http://8%' OR CommandLine LIKE '% -i:http://9%' OR CommandLine LIKE '% -i:https://1%' OR CommandLine LIKE '% -i:https://2%' OR CommandLine LIKE '% -i:https://3%' OR CommandLine LIKE '% -i:https://4%' OR CommandLine LIKE '% -i:https://5%' OR CommandLine LIKE '% -i:https://6%' OR CommandLine LIKE '% -i:https://7%' OR CommandLine LIKE '% -i:https://8%' OR CommandLine LIKE '% -i:https://9%')))
