-- Title: Remote File Download Via Findstr.EXE
-- ID: 587254ee-a24b-4335-b3cd-065c0f1f4baa
-- Status: test
-- Level: medium
-- Author: Furkan CALISKAN, @caliskanfurkan_, @oscd_initiative, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2020-10-05
-- Tags: attack.credential-access, attack.command-and-control, attack.stealth, attack.t1218, attack.t1564.004, attack.t1552.001, attack.t1105
-- Description: Detects execution of "findstr" with specific flags and a remote share path. This specific set of CLI flags would allow "findstr" to download the content of the file located on the remote share as described in the LOLBAS entry.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%findstr%') OR (Image="*findstr.exe") OR (OriginalFileName = 'FINDSTR.EXE')) AND ((CommandLine LIKE '% -v %') AND (CommandLine LIKE '% -l %') AND (CommandLine LIKE '%\\\\\\\\%')))
