# Playbook Schema

This document defines the standard structure for Security Playbooks in this repository. It is intended to ensure playbooks are consistent, machine-readable, reviewable, and testable across detection engineering, incident response, threat hunting, and SOC workflows.

## Purpose

A playbook is a structured operational workflow that describes:

- the scenario being investigated or responded to
- the required inputs and context
- the ordered actions to perform
- the detection logic, data sources, and evidence involved
- expected outputs and follow-up actions
- validation and documentation requirements

The schema below should be used for all playbooks in the repository unless a specialized format is explicitly required by a platform or workflow.
