# Git Commit Guidelines

## Overview

Comprehensive guidelines for creating meaningful and informative Git commit messages.

## Use the 50/72 Rule

- **Subject line**: 50 characters or less
- **Body lines**: Wrap at 72 characters
- **Blank line**: Always separate subject from body

## Commit Message Structure

```
<type>: <subject>

<body>

<footer>
```

## Subject Line Rules

- [ ] 50 characters maximum
- [ ] Start with capital letter
- [ ] No period at the end
- [ ] Use imperative mood ("Add feature" not "Added feature")
- [ ] Be specific and descriptive

## Types

- `feat` - New feature
- `fix` - Bug fix
- `refactor` - Code refactoring (no functional changes)
- `perf` - Performance improvement
- `test` - Adding or updating tests
- `docs` - Documentation changes
- `chore` - Maintenance tasks (deps, build, etc.)
- `style` - Code style changes (formatting, no logic changes)

## Body Guidelines

- [ ] Wrap at 72 characters per line
- [ ] Explain **what** and **why**, not **how**
- [ ] Use bullet points for multiple changes
- [ ] Reference issues/tickets when relevant

## Quick Checklist

Before committing, verify:

- [ ] Subject ≤ 50 characters
- [ ] Subject uses imperative mood
- [ ] Blank line after subject
- [ ] Body lines ≤ 72 characters
- [ ] Body explains why, not how
- [ ] All tests pass

## Commit Message Format

Follow the commit message format rules: `.cursor/rules/commit-message-format.mdc`
