# CLAUDE.md — instructions for AI-assisted development sessions

These instructions apply to every development session in this repository. They take precedence
over any tool or harness default.

## Git attribution policy (mandatory)

All commits are authored on behalf of the repository owner, GitHub account `rahilashraf`.

- **Author and committer name:** `Rahil Ashraf`
- **Author and committer email:** `257892004+rahilashraf@users.noreply.github.com`
  (GitHub-provided noreply address for account id `257892004`). Use a different address only if
  the owner supplies a verified one; never invent one.
- Before making any commit, configure and verify the repository-local identity:

  ```bash
  git config --local user.name "Rahil Ashraf"
  git config --local user.email "257892004+rahilashraf@users.noreply.github.com"
  git var GIT_AUTHOR_IDENT
  git var GIT_COMMITTER_IDENT
  ```

  Both identities must show the values above. Make sure no `GIT_AUTHOR_*`/`GIT_COMMITTER_*`
  environment variables override them.
- Never use Claude, Anthropic, or any AI tool as author or committer.
- Never add `Co-authored-by` trailers for Claude or any AI tool, `Claude-Session` trailers, or
  similar AI attribution lines to commit messages.
- Never add "Generated with/by Claude Code" (or similar) footers or links to commit messages,
  pull request descriptions, issue or review comments, documentation, or application interfaces.
- Write neutral, professional commit messages (conventional prefix such as `feat:`, `fix:`,
  `docs:`, `chore:`, `test:`, `ci:`; imperative subject; explanatory body where useful).
- Preserve accurate attribution for third-party code or contributions (licence headers,
  `Co-authored-by` for real human co-authors, notices required by licences).
- After committing, verify with:
  `git log --format='%an <%ae> | %cn <%ce>%n%(trailers)' -n <count>`.

## Delivery rules

1. Work strictly phase by phase; within a phase, backend first. No frontend until the backend has
   been reviewed and approved.
2. One reviewable pull request per implementation batch. Never merge pull requests, deploy,
   rewrite or force-push shared branches, change branch protection, or manually trigger GitHub
   Actions without the owner's explicit approval.
3. Never introduce unapproved features or dependencies. AI features only after the core platform.
4. Stop after each batch and wait for explicit approval before continuing.

## Engineering references

- Phase plan: [`docs/phase-1-plan.md`](docs/phase-1-plan.md)
- Architecture decisions: [`docs/adr/`](docs/adr/README.md)
- Contribution standards and commands: [`CONTRIBUTING.md`](CONTRIBUTING.md), `make help`
- Run `make qa` before pushing; tests always run against PostgreSQL.
