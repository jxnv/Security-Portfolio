-- Title: Curl File Upload To File Sharing Websites
-- ID: e328cc73-f92a-42fb-b3fa-7c2cffda981a
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-03-29
-- Tags: attack.exfiltration, attack.t1567.002
-- Description: Detects usage of curl to upload files to known file sharing domains, which may indicate data exfiltration.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%0x0.st%' OR CommandLine LIKE '%bashupload.com%' OR CommandLine LIKE '%chunk.io%' OR CommandLine LIKE '%file.io%' OR CommandLine LIKE '%filebin.net%' OR CommandLine LIKE '%pastebin%' OR CommandLine LIKE '%send.firefox.com%' OR CommandLine LIKE '%temp.sh%' OR CommandLine LIKE '%transfer.sh%' OR CommandLine LIKE '%ufile.io%' OR CommandLine LIKE '%uploadfiles.io%' OR CommandLine LIKE '%wetransfer.com%' OR CommandLine LIKE '%x0.at%')) AND (((CommandLine LIKE '% --form%' OR CommandLine LIKE '% --upload-file%' OR CommandLine LIKE '% --data%' OR CommandLine LIKE '% -X POST%' OR CommandLine LIKE '% --request POST %')) OR ((CommandLine=regex("\\s-[FTd]\\s") OR CommandLine=regex("\\s-sT\\s")))) AND ((Image="*\\curl.exe") OR (OriginalFileName = 'curl.exe')))
