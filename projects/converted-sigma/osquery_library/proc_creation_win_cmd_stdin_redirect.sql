-- Title: Read Contents From Stdin Via Cmd.EXE
-- ID: 241e802a-b65e-484f-88cd-c2dc10f9206d
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-03-07
-- Tags: attack.execution, attack.t1059.003
-- Description: Detect the use of "<" to read and potentially execute a file via cmd.exe
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '%<%') AND ((OriginalFileName = 'Cmd.Exe') OR (Image="*\\cmd.exe")))
