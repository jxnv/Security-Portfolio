-- Title: Console CodePage Lookup Via CHCP
-- ID: 7090adee-82e2-4269-bd59-80691e7c6338
-- Status: test
-- Level: medium
-- Author: _pete_0, TheDFIRReport
-- Date: 2022-02-21
-- Tags: attack.discovery, attack.t1614.001
-- Description: Detects use of chcp to look up the system locale value as part of host discovery
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (ParentImage="*\\cmd.exe" AND (ParentCommandLine LIKE '% -c %' OR ParentCommandLine LIKE '% -r %' OR ParentCommandLine LIKE '% -k %') AND Image="*\\chcp.com" AND (CommandLine="*chcp" OR CommandLine="*chcp " OR CommandLine="*chcp  "))
