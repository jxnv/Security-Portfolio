-- Title: Suspicious File Execution From Internet Hosted WebDav Share
-- ID: f0507c0f-a3a2-40f5-acc6-7f543c334993
-- Status: test
-- Level: high
-- Author: pH-T (Nextron Systems)
-- Date: 2022-09-01
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects the execution of the "net use" command to mount a WebDAV server and then immediately execute some content in it. As seen being used in malicious LNK files
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% net use http%' AND CommandLine LIKE '%& start /b %' AND CommandLine LIKE '%\\DavWWWRoot\\%')) AND ((CommandLine LIKE '%.exe %' OR CommandLine LIKE '%.dll %' OR CommandLine LIKE '%.bat %' OR CommandLine LIKE '%.vbs %' OR CommandLine LIKE '%.ps1 %')) AND ((Image LIKE '%\\cmd.exe%') OR (OriginalFileName = 'Cmd.EXE')))
