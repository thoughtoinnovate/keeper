Feature: Due date timeline

  Scenario: Show due timeline with overdue tasks
    Given a fresh keeper home
    When I start the daemon with password "pass123"
    And I add a note "Old task" in bucket "@default/work" with priority "!p2" and due date "^2020-01-01"
    And I add a note "Soon task" in bucket "@default/work" with priority "!p1" and due date "^2026-02-01"
    When I run due timeline
    Then the output should contain "Overdue"
    And the output should contain "Due Timeline"
    And I stop the daemon

  Scenario: Show mermaid due timeline code
    Given a fresh keeper home
    When I start the daemon with password "pass123"
    And I add a note "Soon task" in bucket "@default/work" with priority "!p1" and due date "^2026-02-01"
    When I run due timeline with mermaid
    Then the output should contain "timeline"
    And I stop the daemon
