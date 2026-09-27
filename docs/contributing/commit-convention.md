# Commit Convention

Commit messages must follow a consistent format to improve repository history, change tracking, review processes, and release management.

## Format

```text
<type>(<scope>): <description>
```

The `scope` identifies the affected area of the repository and is optional when a commit affects the project broadly.

Examples:

```text
feat(auth): add email authentication
fix(ci): correct Sigma validation
docs(readme): update installation instructions
```

## Types

| Type       | Description                                                                |
| ---------- | -------------------------------------------------------------------------- |
| `feat`     | Introduces a new feature or capability                                     |
| `fix`      | Fixes a bug, defect, or incorrect behavior                                 |
| `docs`     | Changes documentation only                                                 |
| `refactor` | Changes code structure without changing intended behavior                  |
| `test`     | Adds, updates, or modifies tests                                           |
| `chore`    | Changes build processes, dependencies, configuration, or auxiliary tooling |
| `style`    | Changes formatting, whitespace, or code style without changing logic       |

## Scope

The scope identifies the primary component affected by the commit.

Common scopes include:

- `ci` — Continuous integration and GitHub Actions
- `config` — Configuration files and repository settings
- `detection` — Detection rules and detection metadata
- `docs` — Documentation
- `playbooks` — Security playbooks
- `registry` — Detection or playbook registries
- `scripts` — Automation and utility scripts
- `tests` — Test suites and test fixtures
- `validation` — Validation and repository quality checks

Use the most specific applicable scope.

When a change affects multiple unrelated areas and no single scope is appropriate, the scope may be omitted.

## Description

Commit descriptions must:

- use imperative language;
- begin with a lowercase letter;
- clearly describe the change;
- remain concise and specific;
- not end with a period.

Examples:

```text
fix(ci): correct Sigma test validation
```

```text
docs(playbooks): update persistence documentation
```

```text
feat(detection): add WMI event subscription rule
```

Avoid vague descriptions such as:

```text
fix: update stuff
```

```text
chore: changes
```

```text
update files
```

## Commit Message Guidelines

Each commit should represent one logical change whenever practical.

Prefer focused commits that are easy to review, revert, and audit.

Examples:

```text
fix(ci): correct repository validation
```

```text
fix(registry): correct detection rule metadata
```

```text
test(sigma): add encoded PowerShell test case
```

```text
docs(playbooks): standardize investigation procedures
```

## Breaking Changes

Changes that require consumers, integrations, or repository users to modify their existing usage must be explicitly identified as breaking changes.

Use:

```text
feat(api)!: change authentication response format
```

or include a footer:

```text
BREAKING CHANGE: authentication response format has changed
```

Breaking changes should be documented in the relevant changelog or release documentation.

## Examples

### Feature

```text
feat(playbooks): add WMI event subscription playbook
```

### Bug Fix

```text
fix(ci): correct PowerShell Sigma validation
```

### Documentation

```text
docs(readme): update repository structure
```

### Refactoring

```text
refactor(validation): simplify playbook validation logic
```

### Tests

```text
test(sigma): add encoded PowerShell detection fixture
```

### Build or Tooling

```text
chore(deps): update development dependencies
```

### Formatting

```text
style(yaml): normalize registry indentation
```

## Recommended Structure

Use the following pattern for repository commits:

```text
<type>(<scope>): <description>
```

Keep commits focused, auditable, and representative of a single logical change.
