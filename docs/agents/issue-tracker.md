# Issue tracker: GitHub

Issues and feature specifications live in GitHub Issues on `eudi-dev/eudi-dev`. Run `gh` from this checkout so it uses the Git remote to find the repository.

## Common commands

- Read an issue: `gh issue view <number> --comments`.
- List issues: `gh issue list --state open --json number,title,body,labels,comments`. Add `--label` or change `--state` as needed.
- Create an issue: `gh issue create --title "..." --body-file <file>`.
- Comment: `gh issue comment <number> --body-file <file>`.
- Change labels: `gh issue edit <number> --add-label "..."` or `--remove-label "..."`.
- Close an issue: `gh issue close <number> --comment "..."`.

Use a file for multiline bodies to preserve formatting and avoid shell expansion.

## Pull requests

**PRs as a request surface: no.** `/triage` reads this setting. File feature requests as issues.

Read a PR with `gh pr view <number> --comments` and inspect its changes with `gh pr diff <number>`.

Issues and PRs share a number space. For an ambiguous reference such as `#42`, try `gh pr view 42`, then `gh issue view 42`.

## Skill conventions

“Publish to the issue tracker” means create a GitHub issue. “Fetch the relevant ticket” means read the issue and its comments.
