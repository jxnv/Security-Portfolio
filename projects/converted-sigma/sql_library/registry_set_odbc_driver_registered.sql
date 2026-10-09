-- Title: New ODBC Driver Registered
-- ID: 3390fbef-c98d-4bdd-a863-d65ed7c610dd
-- Status: test
-- Level: low
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-23
-- Tags: attack.persistence
-- Description: Detects the registration of a new ODBC driver.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetObject ILIKE '%\\SOFTWARE\\ODBC\\ODBCINST.INI\\%' AND TargetObject ILIKE '%\\Driver') AND NOT ((TargetObject ILIKE '%\\SQL Server\\%' AND Details = '%WINDIR%\\System32\\SQLSRV32.dll')) AND NOT (((TargetObject ILIKE '%\\Microsoft Access %' AND Details ILIKE 'C:\\Progra%' AND Details ILIKE '%\\ACEODBC.DLL') OR (TargetObject ILIKE '%\\Microsoft Excel Driver%' AND Details ILIKE 'C:\\Progra%' AND Details ILIKE '%\\ACEODBC.DLL'))))
