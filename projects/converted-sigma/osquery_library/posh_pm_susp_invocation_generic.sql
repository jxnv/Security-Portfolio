-- Title: Suspicious PowerShell Invocations - Generic - PowerShell Module
-- ID: bbb80e91-5746-4fbe-8898-122e2cafdbf4
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2017-03-12
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects suspicious PowerShell invocation command parameters
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((ContextInfo LIKE '% -enc %' OR ContextInfo LIKE '% -EncodedCommand %' OR ContextInfo LIKE '% -ec %')) AND ((ContextInfo LIKE '% -w hidden %' OR ContextInfo LIKE '% -window hidden %' OR ContextInfo LIKE '% -windowstyle hidden %' OR ContextInfo LIKE '% -w 1 %')) AND ((ContextInfo LIKE '% -noni %' OR ContextInfo LIKE '% -noninteractive %')))
