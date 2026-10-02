# Playbook Writing Guide

This section outlines the processes for adding a new playbook to the Security Playbooks project, updating an existing playbook, and the review procedure.

Playbooks are used solely for training, defense, threat hunting, detection engineering, incident response, validation, and explicitly authorized security testing.

## Before You Begin

Before creating a new playbook:

1. Check if there is an existing playbook under `playbooks/` that addresses the same behavior.
2. Review the [Playbook Guide](playbook-guide.md).
3. Use the [Playbook Template](../templates/playbook-template.md).
4. Define the primary objective of the playbook.
5. Select the appropriate MITRE ATT&CK technique or operational category.
6. Identify the necessary logs, telemetry, and security tools.
7. Check for relevant detection rules, threat hunting queries, lab scenarios, or response playbooks.
8. Avoid creating a new playbook that duplicates an existing one.

If an existing playbook can be extended, update the existing file instead of creating a new one.
