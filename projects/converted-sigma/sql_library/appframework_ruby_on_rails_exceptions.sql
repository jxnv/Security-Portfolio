-- Title: Ruby on Rails Framework Exceptions
-- ID: 0d2c3d4c-4b48-4ac3-8f23-ea845746bb1a
-- Status: stable
-- Level: medium
-- Author: Thomas Patzke
-- Date: 2017-08-06
-- Tags: attack.initial-access, attack.t1190
-- Description: Detects suspicious Ruby on Rails exceptions that could indicate exploitation attempts
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ("ActionController::InvalidAuthenticityToken" OR "ActionController::InvalidCrossOriginRequest" OR "ActionController::MethodNotAllowed" OR "ActionController::BadRequest" OR "ActionController::ParameterMissing")
