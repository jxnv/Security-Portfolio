-- Title: Curl File Upload To File Sharing Websites
-- ID: e328cc73-f92a-42fb-b3fa-7c2cffda981a
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2026-03-29
-- Tags: attack.exfiltration, attack.t1567.002
-- Description: Detects usage of curl to upload files to known file sharing domains, which may indicate data exfiltration.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%0x0.st%' OR CommandLine ILIKE '%bashupload.com%' OR CommandLine ILIKE '%chunk.io%' OR CommandLine ILIKE '%file.io%' OR CommandLine ILIKE '%filebin.net%' OR CommandLine ILIKE '%pastebin%' OR CommandLine ILIKE '%send.firefox.com%' OR CommandLine ILIKE '%temp.sh%' OR CommandLine ILIKE '%transfer.sh%' OR CommandLine ILIKE '%ufile.io%' OR CommandLine ILIKE '%uploadfiles.io%' OR CommandLine ILIKE '%wetransfer.com%' OR CommandLine ILIKE '%x0.at%')) AND (((CommandLine ILIKE '% --form%' OR CommandLine ILIKE '% --upload-file%' OR CommandLine ILIKE '% --data%' OR CommandLine ILIKE '% -X POST%' OR CommandLine ILIKE '% --request POST %')) OR ((REGEXP_LIKE(CommandLine, '\s-[FTd]\s') OR REGEXP_LIKE(CommandLine, '\s-sT\s')))) AND ((Image ILIKE '%\\curl.exe') OR (OriginalFileName = 'curl.exe')))
