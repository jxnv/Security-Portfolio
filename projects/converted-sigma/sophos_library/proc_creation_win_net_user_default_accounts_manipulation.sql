-- Title: Suspicious Manipulation Of Default Accounts Via Net.EXE
-- ID: 5b768e71-86f2-4879-b448-81061cbae951
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-01
-- Tags: attack.collection, attack.t1560.001
-- Description: Detects suspicious manipulations of default accounts such as 'administrator' and 'guest'. For example 'enable' or 'disable' accounts or change the password...etc
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((((Image ILIKE '%\\net.exe' OR Image ILIKE '%\\net1.exe')) OR ((OriginalFileName = 'net.exe' OR OriginalFileName = 'net1.exe'))) AND (CommandLine ILIKE '% user %') AND ((CommandLine ILIKE '% Järjestelmänvalvoja %' OR CommandLine ILIKE '% Rendszergazda %' OR CommandLine ILIKE '% Администратор %' OR CommandLine ILIKE '% Administrateur %' OR CommandLine ILIKE '% Administrador %' OR CommandLine ILIKE '% Administratör %' OR CommandLine ILIKE '% Administrator %' OR CommandLine ILIKE '% guest %' OR CommandLine ILIKE '% DefaultAccount %' OR CommandLine ILIKE '% \"Järjestelmänvalvoja\" %' OR CommandLine ILIKE '% \"Rendszergazda\" %' OR CommandLine ILIKE '% \"Администратор\" %' OR CommandLine ILIKE '% \"Administrateur\" %' OR CommandLine ILIKE '% \"Administrador\" %' OR CommandLine ILIKE '% \"Administratör\" %' OR CommandLine ILIKE '% \"Administrator\" %' OR CommandLine ILIKE '% \"guest\" %' OR CommandLine ILIKE '% \"DefaultAccount\" %' OR CommandLine ILIKE '% 'Järjestelmänvalvoja' %' OR CommandLine ILIKE '% 'Rendszergazda' %' OR CommandLine ILIKE '% 'Администратор' %' OR CommandLine ILIKE '% 'Administrateur' %' OR CommandLine ILIKE '% 'Administrador' %' OR CommandLine ILIKE '% 'Administratör' %' OR CommandLine ILIKE '% 'Administrator' %' OR CommandLine ILIKE '% 'guest' %' OR CommandLine ILIKE '% 'DefaultAccount' %'))) AND NOT (((CommandLine ILIKE '%guest%' AND CommandLine ILIKE '%/active no%'))))
