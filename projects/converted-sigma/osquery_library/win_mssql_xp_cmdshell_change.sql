-- Title: MSSQL XPCmdshell Option Change
-- ID: d08dd86f-681e-4a00-a92c-1db218754417
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-07-12
-- Tags: attack.execution
-- Description: Detects when the MSSQL "xp_cmdshell" stored procedure setting is changed.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (Provider_Name LIKE '%MSSQL%' AND EventID = '15457' AND Data LIKE '%xp_cmdshell%')
