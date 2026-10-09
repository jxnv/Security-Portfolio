-- Title: Console CodePage Lookup Via CHCP
-- ID: 7090adee-82e2-4269-bd59-80691e7c6338
-- Status: test
-- Level: medium
-- Author: _pete_0, TheDFIRReport
-- Date: 2022-02-21
-- Tags: attack.discovery, attack.t1614.001
-- Description: Detects use of chcp to look up the system locale value as part of host discovery
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (ParentImage ILIKE '%\\cmd.exe' AND (ParentCommandLine ILIKE '% -c %' OR ParentCommandLine ILIKE '% -r %' OR ParentCommandLine ILIKE '% -k %') AND Image ILIKE '%\\chcp.com' AND (CommandLine ILIKE '%chcp' OR CommandLine ILIKE '%chcp ' OR CommandLine ILIKE '%chcp  '))
