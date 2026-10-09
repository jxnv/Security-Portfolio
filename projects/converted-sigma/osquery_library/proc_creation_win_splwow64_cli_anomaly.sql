-- Title: Suspicious Splwow64 Without Params
-- ID: 1f1a8509-2cbb-44f5-8751-8e1571518ce2
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-08-23
-- Tags: attack.stealth, attack.t1202
-- Description: Detects suspicious Splwow64.exe process without any command line parameters
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (Image="*\\splwow64.exe" AND CommandLine="*splwow64.exe")
