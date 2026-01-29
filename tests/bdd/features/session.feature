Feature: Session management

  Scenario: Start, status, and stop
    Given a fresh keeper home
    When I start the daemon with password "pass123"
    Then the daemon status should be running
    When I stop the daemon
    Then the daemon status should be stopped

  Scenario: Start with a relative vault directory
    Given a fresh keeper home
    And a vault directory "vault-dir"
    When I start the daemon with password "pass123" and vault "vault-dir"
    Then the vault database should exist at "vault-dir/vault.db"
    And the keystore should exist at "vault-dir/keystore.json"
    And I stop the daemon

  Scenario: Start with an explicit vault file path
    Given a fresh keeper home
    And a vault file "custom.db"
    When I start the daemon with password "pass123" and vault "custom.db"
    Then the vault database should exist at "custom.db"
    And the keystore should exist at "keystore.json"
    And I stop the daemon

  Scenario: Password confirmation mismatch on first run
    Given a fresh keeper home
    When I attempt to start with passwords "pass123" and "wrongpass"
    Then the command should fail with message "Passwords do not match"
