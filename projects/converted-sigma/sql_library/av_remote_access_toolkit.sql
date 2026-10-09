-- Title: Antivirus - Remote Access Tools Signature
-- ID: 97233998-3838-4581-88c6-f1d19d3993fb
-- Status: experimental
-- Level: critical
-- Author: Arnim Rupp (Nextron Systems)
-- Date: 2026-06-15
-- Tags: attack.execution, attack.t1203, attack.command-and-control, attack.t1219.002
-- Description: Detects a highly relevant Antivirus alert that reports a remote access tool.
-- This event must not be ignored just because the AV has blocked the malware but investigate, how it came there in the first place.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Signature ILIKE '%AgentB%' OR Signature ILIKE '%AgentTesla%' OR Signature ILIKE '%AMRat%' OR Signature ILIKE '%Ammyy%' OR Signature ILIKE '%AsyncRAT%' OR Signature ILIKE '%Bandook%' OR Signature ILIKE '%Bitrat%' OR Signature ILIKE '%Bladabindi%' OR Signature ILIKE '%Connectwise%' OR Signature ILIKE '%CyberGate%' OR Signature ILIKE '%DarkComet%' OR Signature ILIKE '%DCrat%' OR Signature ILIKE '%Delf%' OR Signature ILIKE '%DokStorm%' OR Signature ILIKE '%Egairtigado%' OR Signature ILIKE '%Gh0st%' OR Signature ILIKE '%Gorat%' OR Signature ILIKE '%GodRat%' OR Signature ILIKE '%Jalapeno%' OR Signature ILIKE '%LummaC2%' OR Signature ILIKE '%Minirat%' OR Signature ILIKE '%Netwire%' OR Signature ILIKE '%NanoCore%' OR Signature ILIKE '%NJRat%' OR Signature ILIKE '%Paralax%' OR Signature ILIKE '%PlugX%' OR Signature ILIKE '%Pulsar%' OR Signature ILIKE '%Quasar%' OR Signature ILIKE '%Remcos%' OR Signature ILIKE '%Ravartar%' OR Signature ILIKE '%RemoteAdmin%' OR Signature ILIKE '%RemoteTool%' OR Signature ILIKE '%revengeRAT%' OR Signature ILIKE '%rokRAT%' OR Signature ILIKE '%salatstealer%' OR Signature ILIKE '%Salgorea%' OR Signature ILIKE '%SmokedHam%' OR Signature ILIKE '%TigerRat%' OR Signature ILIKE '%Tzeebot%' OR Signature ILIKE '%WarZone%' OR Signature ILIKE '%VenomRAT%' OR Signature ILIKE '%Vidar%' OR Signature ILIKE '%Wirenet%' OR Signature ILIKE '%XWorm%' OR Signature ILIKE '%Zapchast%' OR Signature ILIKE '%Zegost%'))
