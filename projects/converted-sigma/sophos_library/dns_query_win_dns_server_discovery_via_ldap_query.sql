-- Title: DNS Server Discovery Via LDAP Query
-- ID: a21bcd7e-38ec-49ad-b69a-9ea17e69509e
-- Status: test
-- Level: low
-- Author: frack113
-- Date: 2022-08-20
-- Tags: attack.discovery, attack.t1482
-- Description: Detects DNS server discovery via LDAP query requests from uncommon applications
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((QueryName ILIKE '_ldap.%') AND NOT (((Image ILIKE '%:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\%' AND Image ILIKE '%\\MsMpEng.exe') OR ((Image ILIKE '%:\\Program Files\\%' OR Image ILIKE '%:\\Program Files (x86)\\%' OR Image ILIKE '%:\\Windows\\%')) OR (Image IS NULL) OR (Image = '<unknown process>'))) AND NOT (((Image ILIKE 'C:\\WindowsAzure\\GuestAgent%') OR ((Image ILIKE '%\\chrome.exe' OR Image ILIKE '%\\firefox.exe' OR Image ILIKE '%\\opera.exe')))))
