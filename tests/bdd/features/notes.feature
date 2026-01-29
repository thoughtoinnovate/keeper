Feature: Notes and tasks

  Scenario: Capture and retrieve a task
    Given a fresh keeper home
    When I start the daemon with password "pass123"
    And I add a note "Fix auth bug" in bucket "@work" with priority "!p1" and due date "^2026-02-01"
    Then the output should contain "[✓] Saved"
    When I get notes for bucket "@work"
    Then the output should contain "Fix auth bug"
    And I stop the daemon

  Scenario: Duplicate detection
    Given a fresh keeper home
    When I start the daemon with password "pass123"
    And I add a note "Duplicate test" in bucket "@inbox" with priority "!p2" and due date "^2026-02-02"
    And I add a note "Duplicate test" in bucket "@inbox" with priority "!p2" and due date "^2026-02-02"
    Then the output should contain "Duplicate ignored"
    And I stop the daemon

  Scenario: Missing note content
    Given a fresh keeper home
    When I run "note" with no content
    Then the command should fail with message "Note content cannot be empty"

  Scenario: Invalid due date is rejected
    Given a fresh keeper home
    When I start the daemon with password "pass123"
    And I add a note "Bad date" in bucket "@work" with priority "!p1" and due date "^2026-02-99"
    Then the command should fail with message "Invalid due date"
    And I stop the daemon
