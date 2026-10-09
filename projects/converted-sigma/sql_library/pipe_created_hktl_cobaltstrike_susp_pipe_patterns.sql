-- Title: CobaltStrike Named Pipe Patterns
-- ID: 85adeb13-4fc9-4e68-8a4a-c7cb2c336eb7
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Christian Burkard (Nextron Systems)
-- Date: 2021-07-30
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1055, stp.1k
-- Description: Detects the creation of a named pipe with a pattern found in CobaltStrike malleable C2 profiles
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((PipeName ILIKE '\\Winsock2\\CatalogChangeListener-%' AND PipeName ILIKE '%-0,') OR (((PipeName ILIKE '\\DserNamePipe%' OR PipeName ILIKE '\\f4c3%' OR PipeName ILIKE '\\f53f%' OR PipeName ILIKE '\\fullduplex_%' OR PipeName ILIKE '\\mojo.5688.8052.183894939787088877%' OR PipeName ILIKE '\\mojo.5688.8052.35780273329370473%' OR PipeName ILIKE '\\MsFteWds%' OR PipeName ILIKE '\\msrpc_%' OR PipeName ILIKE '\\mypipe-f%' OR PipeName ILIKE '\\mypipe-h%' OR PipeName ILIKE '\\ntsvcs%' OR PipeName ILIKE '\\PGMessagePipe%' OR PipeName ILIKE '\\rpc_%' OR PipeName ILIKE '\\scerpc%' OR PipeName ILIKE '\\SearchTextHarvester%' OR PipeName ILIKE '\\spoolss%' OR PipeName ILIKE '\\win_svc%' OR PipeName ILIKE '\\win\\msrpc_%' OR PipeName ILIKE '\\windows.update.manager%' OR PipeName ILIKE '\\wkssvc%')) OR ((PipeName = '\\demoagent_11' OR PipeName = '\\demoagent_22')))) AND NOT (((PipeName = '\\wkssvc' OR PipeName = '\\spoolss' OR PipeName = '\\scerpc' OR PipeName = '\\ntsvcs' OR PipeName = '\\SearchTextHarvester' OR PipeName = '\\PGMessagePipe' OR PipeName = '\\MsFteWds'))) AND NOT (((Image ILIKE '%:\\Program Files\\Websense\\%' OR Image ILIKE '%:\\Program Files (x86)\\Websense\\%') AND (PipeName ILIKE '\\DserNamePipeR%' OR PipeName ILIKE '\\DserNamePipeW%'))))
