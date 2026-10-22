---
trigger: always_on
---

# Git Branch Management

Before making any modifications to a project:

1. Check whether the project is a Git repository.
2. Check the current branch and working tree status.
3. If there are uncommitted changes, inform the user and avoid overwriting or mixing existing work.
4. Create a new branch from the current branch, unless the user specifies another base.
5. Use the naming convention `feature/<short-description>` for new features, `fix/<short-description>` for bug fixes, and `refactor/<short-description>` for refactoring.
6. Switch to the new branch before modifying any files.
7. Confirm the new branch is active.
8. Only then begin implementation.

Never make project changes directly on `main` or `master`.

Never automatically merge or push changes without explicit user approval.

If a new branch cannot be created, stop and explain the problem before modifying any files.
