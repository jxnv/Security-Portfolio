-- Title: A Rule Has Been Deleted From The Windows Firewall Exception List
-- ID: c187c075-bb3e-4c62-b4fa-beae0ffc211f
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-02-19
-- Tags: attack.defense-impairment, attack.t1686.003
-- Description: Detects when a single rules or all of the rules have been deleted from the Windows Defender Firewall
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((EventID = '2006' OR EventID = '2052')) AND NOT (((ModifyingApplication = '') OR ((ModifyingApplication="C:\\Program Files (x86)\\*" OR ModifyingApplication="C:\\Program Files\\*" OR ModifyingApplication="C:\\Windows\\WinSxS\\*")) OR (NOT ModifyingApplication=*) OR (ModifyingApplication = 'C:\\Windows\\System32\\svchost.exe'))) AND NOT ((ModifyingApplication="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*" AND ModifyingApplication="*\\MsMpEng.exe")))
