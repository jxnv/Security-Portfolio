-- Title: NtdllPipe Like Activity Execution
-- ID: bbc865e4-7fcd-45a6-8ff1-95ced28ec5b2
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-03-05
-- Tags: attack.defense-impairment
-- Description: Detects command that type the content of ntdll.dll to a different file or a pipe in order to evade AV / EDR detection. As seen being used in the POC NtdllPipe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%type %windir%\\system32\\ntdll.dll%' OR CommandLine LIKE '%type %systemroot%\\system32\\ntdll.dll%' OR CommandLine LIKE '%type c:\\windows\\system32\\ntdll.dll%' OR CommandLine LIKE '%\\\\ntdll.dll > \\\\\\\\.\\\\pipe\\\\%'))
