-- Title: Suspicious PowerShell Invocations - Generic
-- ID: ed965133-513f-41d9-a441-e38076a0798f
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2017-03-12
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects suspicious PowerShell invocation command parameters
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((ScriptBlockText LIKE '% -enc %' OR ScriptBlockText LIKE '% -EncodedCommand %' OR ScriptBlockText LIKE '% -ec %')) AND ((ScriptBlockText LIKE '% -w hidden %' OR ScriptBlockText LIKE '% -window hidden %' OR ScriptBlockText LIKE '% -windowstyle hidden %' OR ScriptBlockText LIKE '% -w 1 %')) AND ((ScriptBlockText LIKE '% -noni %' OR ScriptBlockText LIKE '% -noninteractive %')))
