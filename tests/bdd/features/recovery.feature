Feature: Recovery and password rotation

  Scenario: Recover with a valid recovery code
    Given a fresh keeper home
    When I start the daemon with password "pass123"
    And I stop the daemon
    And I recover the vault using the saved recovery code and new password "newpass123"
    Then the command should succeed
    When I start the daemon with password "newpass123"
    Then the daemon status should be running
    And I stop the daemon

  Scenario: Recover with an invalid recovery code
    Given a fresh keeper home
    When I start the daemon with password "pass123"
    And I stop the daemon
    And I attempt recovery with code "invalid code" and new password "newpass123"
    Then the command should fail with message "Invalid password or recovery code"

  Scenario: Rotate password requires current password
    Given a fresh keeper home
    When I start the daemon with password "pass123"
    And I attempt to rotate password from "wrongpass" to "newpass123"
    Then the command should fail with message "Invalid current password"
    When I rotate password from "pass123" to "newpass123"
    Then the output should contain "Password updated"
    And I stop the daemon
