-- Title: Windows PowerShell User Agent
-- ID: c8557060-9221-4448-8794-96320e6f3e74
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2017-03-13
-- Tags: attack.command-and-control, attack.t1071.001
-- Description: Detects Windows PowerShell Web Access
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (c-useragent LIKE '% WindowsPowerShell/%')
