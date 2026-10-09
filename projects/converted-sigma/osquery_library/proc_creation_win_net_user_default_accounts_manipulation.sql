-- Title: Suspicious Manipulation Of Default Accounts Via Net.EXE
-- ID: 5b768e71-86f2-4879-b448-81061cbae951
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-01
-- Tags: attack.collection, attack.t1560.001
-- Description: Detects suspicious manipulations of default accounts such as 'administrator' and 'guest'. For example 'enable' or 'disable' accounts or change the password...etc
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((((Image="*\\net.exe" OR Image="*\\net1.exe")) OR ((OriginalFileName = 'net.exe' OR OriginalFileName = 'net1.exe'))) AND (CommandLine LIKE '% user %') AND ((CommandLine LIKE '% Järjestelmänvalvoja %' OR CommandLine LIKE '% Rendszergazda %' OR CommandLine LIKE '% Администратор %' OR CommandLine LIKE '% Administrateur %' OR CommandLine LIKE '% Administrador %' OR CommandLine LIKE '% Administratör %' OR CommandLine LIKE '% Administrator %' OR CommandLine LIKE '% guest %' OR CommandLine LIKE '% DefaultAccount %' OR CommandLine LIKE '% \"Järjestelmänvalvoja\" %' OR CommandLine LIKE '% \"Rendszergazda\" %' OR CommandLine LIKE '% \"Администратор\" %' OR CommandLine LIKE '% \"Administrateur\" %' OR CommandLine LIKE '% \"Administrador\" %' OR CommandLine LIKE '% \"Administratör\" %' OR CommandLine LIKE '% \"Administrator\" %' OR CommandLine LIKE '% \"guest\" %' OR CommandLine LIKE '% \"DefaultAccount\" %' OR CommandLine LIKE '% 'Järjestelmänvalvoja' %' OR CommandLine LIKE '% 'Rendszergazda' %' OR CommandLine LIKE '% 'Администратор' %' OR CommandLine LIKE '% 'Administrateur' %' OR CommandLine LIKE '% 'Administrador' %' OR CommandLine LIKE '% 'Administratör' %' OR CommandLine LIKE '% 'Administrator' %' OR CommandLine LIKE '% 'guest' %' OR CommandLine LIKE '% 'DefaultAccount' %'))) AND NOT (((CommandLine LIKE '%guest%' AND CommandLine LIKE '%/active no%'))))
