-- Title: HackTool - SharpWSUS/WSUSpendu Execution
-- ID: b0ce780f-10bd-496d-9067-066d23dc3aa5
-- Status: test
-- Level: high
-- Author: @Kostastsale, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-10-07
-- Tags: attack.execution, attack.lateral-movement, attack.t1210
-- Description: Detects the execution of SharpWSUS or WSUSpendu, utilities that allow for lateral movement through WSUS.
-- Windows Server Update Services (WSUS) is a critical component of Windows systems and is frequently configured in a way that allows an attacker to circumvent internal networking limitations.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% -Inject %') AND ((CommandLine LIKE '% -PayloadArgs %' OR CommandLine LIKE '% -PayloadFile %'))) OR (((CommandLine LIKE '% approve %' OR CommandLine LIKE '% create %' OR CommandLine LIKE '% check %' OR CommandLine LIKE '% delete %')) AND ((CommandLine LIKE '% /payload:%' OR CommandLine LIKE '% /payload=%' OR CommandLine LIKE '% /updateid:%' OR CommandLine LIKE '% /updateid=%'))))
