-- Title: Potential CommandLine Path Traversal Via Cmd.EXE
-- ID: 087790e3-3287-436c-bccf-cbd0184a7db1
-- Status: test
-- Level: high
-- Author: xknow @xknow_infosec, Tim Shelton
-- Date: 2020-06-11
-- Tags: attack.execution, attack.t1059.003
-- Description: Detects potential path traversal attempt via cmd.exe. Could indicate possible command/argument confusion/hijacking
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((((ParentCommandLine LIKE '%/c%' OR ParentCommandLine LIKE '%/k%' OR ParentCommandLine LIKE '%/r%')) OR ((CommandLine LIKE '%/c%' OR CommandLine LIKE '%/k%' OR CommandLine LIKE '%/r%'))) AND ((ParentImage="*\\cmd.exe") OR (Image="*\\cmd.exe") OR (OriginalFileName = 'cmd.exe')) AND ((ParentCommandLine = '/../../') OR (CommandLine LIKE '%/../../%'))) AND NOT ((CommandLine LIKE '%\\Tasktop\\keycloak\\bin\\/../../jre\\bin\\java%')))
