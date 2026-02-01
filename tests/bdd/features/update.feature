Feature: Self-Update with Safety Mechanisms
  As a user
  I want safe updates with automatic rollback
  So that I don't lose access to my vault

  Background:
    Given a temporary directory for testing
    And a migration manifest is configured

  Scenario: Successful update with no breaking changes
    Given the current version is "0.2.0"
    And version "0.2.1" is available
    And version "0.2.1" has no breaking changes
    When I run the update command
    Then the update should proceed without backup
    And the migration check should pass

  Scenario: Update with breaking changes triggers backup
    Given the current version is "0.2.0"
    And version "0.3.0" is available
    And version "0.3.0" has breaking changes
    And I have a vault with password "SecurePass123!"
    When I run the update command
    Then I should be prompted about the breaking changes
    And a pre-update backup should be created
    And the update should proceed

  Scenario: Skip migration check flag
    Given the current version is "0.2.0"
    And version "0.3.0" has breaking changes
    When I run the update command with skip migration check flag
    Then the migration check should be bypassed

  Scenario: Force update flag
    Given the current version is "0.2.0"
    And version "0.3.0" has breaking changes
    When I run the update command with force flag
    Then the update should proceed even with migration warnings
