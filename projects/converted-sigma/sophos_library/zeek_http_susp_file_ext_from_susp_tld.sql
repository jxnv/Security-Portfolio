-- Title: HTTP Request to Low Reputation TLD or Suspicious File Extension
-- ID: 68c2c604-92ad-468b-bf4a-aac49adad08c
-- Status: experimental
-- Level: medium
-- Author: @signalblur, Corelight
-- Date: 2025-02-26
-- Tags: attack.initial-access, attack.command-and-control
-- Description: Detects HTTP requests to low reputation TLDs (e.g. .xyz, .top, .ru) or ending in suspicious file extensions (.exe, .dll, .hta), which may indicate malicious activity.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((host ILIKE '%.bid' OR host ILIKE '%.by' OR host ILIKE '%.cf' OR host ILIKE '%.click' OR host ILIKE '%.cm' OR host ILIKE '%.ga' OR host ILIKE '%.gq' OR host ILIKE '%.ir' OR host ILIKE '%.kp' OR host ILIKE '%.loan' OR host ILIKE '%.ml' OR host ILIKE '%.mm' OR host ILIKE '%.party' OR host ILIKE '%.pw' OR host ILIKE '%.ru' OR host ILIKE '%.su' OR host ILIKE '%.sy' OR host ILIKE '%.tk' OR host ILIKE '%.top' OR host ILIKE '%.tv' OR host ILIKE '%.ve' OR host ILIKE '%.work' OR host ILIKE '%.xyz')) AND (((uri ILIKE '%.bat' OR uri ILIKE '%.bin' OR uri ILIKE '%.cmd' OR uri ILIKE '%.cpl' OR uri ILIKE '%.dll' OR uri ILIKE '%.dylib' OR uri ILIKE '%.elf' OR uri ILIKE '%.exe' OR uri ILIKE '%.hta' OR uri ILIKE '%.iso' OR uri ILIKE '%.jar' OR uri ILIKE '%.js' OR uri ILIKE '%.lnk' OR uri ILIKE '%.msi' OR uri ILIKE '%.pif' OR uri ILIKE '%.ps1' OR uri ILIKE '%.py' OR uri ILIKE '%.reg' OR uri ILIKE '%.scr' OR uri ILIKE '%.sh' OR uri ILIKE '%.so' OR uri ILIKE '%.vbs' OR uri ILIKE '%.wsf')) OR ((resp_mime_types = 'application/vnd.microsoft.portable-executable' OR resp_mime_types = 'application/x-bat' OR resp_mime_types = 'application/x-dosexec' OR resp_mime_types = 'application/x-elf' OR resp_mime_types = 'application/x-iso9660-image' OR resp_mime_types = 'application/x-java-archive' OR resp_mime_types = 'application/x-ms-shortcut' OR resp_mime_types = 'application/x-msdos-program' OR resp_mime_types = 'application/x-msdownload' OR resp_mime_types = 'application/x-python-code' OR resp_mime_types = 'application/x-sh'))))
