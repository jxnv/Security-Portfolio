-- Title: AWS Bedrock Guardrail Updated
-- ID: 1c722651-254a-4b04-a9f4-99b62a2d0a1f
-- Status: experimental
-- Level: medium
-- Author: Marco Pedrinazzi (@pedrinazziM) (InTheCyber)
-- Date: 2026-07-10
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects updates to an Amazon Bedrock guardrail, which may indicate attempts to weaken
-- model safety controls and allow unsafe or unauthorized model responses.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (eventName = 'UpdateGuardrail' AND eventSource = 'bedrock.amazonaws.com')
