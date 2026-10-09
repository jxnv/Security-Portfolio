-- Title: New ODBC Driver Registered
-- ID: 3390fbef-c98d-4bdd-a863-d65ed7c610dd
-- Status: test
-- Level: low
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-23
-- Tags: attack.persistence
-- Description: Detects the registration of a new ODBC driver.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetObject LIKE '%\\SOFTWARE\\ODBC\\ODBCINST.INI\\%' AND TargetObject="*\\Driver") AND NOT ((TargetObject LIKE '%\\SQL Server\\%' AND Details = '%WINDIR%\\System32\\SQLSRV32.dll')) AND NOT (((TargetObject LIKE '%\\Microsoft Access %' AND Details="C:\\Progra*" AND Details="*\\ACEODBC.DLL") OR (TargetObject LIKE '%\\Microsoft Excel Driver%' AND Details="C:\\Progra*" AND Details="*\\ACEODBC.DLL"))))
