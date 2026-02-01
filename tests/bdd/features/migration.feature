Feature: Data Migration Between Versions
  As a user
  I want my data to be preserved during updates
  So that I don't lose my vault contents

  Background:
    Given a temporary directory for testing
    And a migration manifest with no breaking changes for version "0.2.1"

  Scenario: Update with no breaking changes
    Given the current version is "0.2.0"
    And the target version is "0.2.1"
    When I check if migration is needed
    Then no migration should be required

  Scenario: Update with breaking changes requires backup
    Given the current version is "0.2.0"
    And the target version is "0.3.0"
    And version "0.3.0" has breaking changes requiring migration
    When I check if migration is needed
    Then migration should be required
    And the migration type should be "full_export_import"

  Scenario: Migration check shows incompatible versions
    Given the current version is "0.3.0"
    And the target version is "0.2.0"
    When I check if migration is needed
    Then migration should be incompatible

  Scenario: Manual migration check command
    Given the current version is "0.2.0"
    When I run the migrate check command
    Then I should see the current version
    And I should see if migration is needed

  Scenario: Manual backup creation
    Given a vault exists with password "SecurePass123!"
    When I run the migrate backup command
    And I enter the password "SecurePass123!"
    Then a backup should be created
    And the backup should be verifiable

  Scenario: Manual restore from backup
    Given a backup exists for version "0.2.0"
    And the vault is in a modified state
    When I run the migrate restore command with the backup
    And I enter the password "SecurePass123!"
    Then the vault should be restored to version "0.2.0"

  Scenario: List available backups
    Given 3 backups exist
    When I run the migrate list command
    Then I should see 3 backups listed
    And the most recent backup should be first
