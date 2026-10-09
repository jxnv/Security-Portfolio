-- Title: Download From Suspicious TLD - Whitelist
-- ID: b5de2919-b74a-4805-91a7-5049accbaefe
-- Status: test
-- Level: low
-- Author: Florian Roth (Nextron Systems)
-- Date: 2017-03-13
-- Tags: attack.initial-access, attack.t1566, attack.execution, attack.t1203, attack.t1204.002
-- Description: Detects executable downloads from suspicious remote systems
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((c-uri-extension = 'exe' OR c-uri-extension = 'vbs' OR c-uri-extension = 'bat' OR c-uri-extension = 'rar' OR c-uri-extension = 'ps1' OR c-uri-extension = 'doc' OR c-uri-extension = 'docm' OR c-uri-extension = 'xls' OR c-uri-extension = 'xlsm' OR c-uri-extension = 'pptm' OR c-uri-extension = 'rtf' OR c-uri-extension = 'hta' OR c-uri-extension = 'dll' OR c-uri-extension = 'ws' OR c-uri-extension = 'wsf' OR c-uri-extension = 'sct' OR c-uri-extension = 'zip')) AND NOT (((cs-host ILIKE '%.com' OR cs-host ILIKE '%.org' OR cs-host ILIKE '%.net' OR cs-host ILIKE '%.edu' OR cs-host ILIKE '%.gov' OR cs-host ILIKE '%.uk' OR cs-host ILIKE '%.ca' OR cs-host ILIKE '%.de' OR cs-host ILIKE '%.jp' OR cs-host ILIKE '%.fr' OR cs-host ILIKE '%.au' OR cs-host ILIKE '%.us' OR cs-host ILIKE '%.ch' OR cs-host ILIKE '%.it' OR cs-host ILIKE '%.nl' OR cs-host ILIKE '%.se' OR cs-host ILIKE '%.no' OR cs-host ILIKE '%.es'))))
