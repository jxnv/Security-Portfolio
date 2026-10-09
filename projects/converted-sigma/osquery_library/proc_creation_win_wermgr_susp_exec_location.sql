-- Title: Suspicious Execution Location Of Wermgr.EXE
-- ID: 5394fcc7-aeb2-43b5-9a09-cac9fc5edcd5
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-10-14
-- Tags: attack.execution
-- Description: Detects suspicious Windows Error Reporting manager (wermgr.exe) execution location.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((Image="*\\wermgr.exe") AND NOT (((Image="C:\\Windows\\System32\\*" OR Image="C:\\Windows\\SysWOW64\\*" OR Image="C:\\Windows\\WinSxS\\*"))))
