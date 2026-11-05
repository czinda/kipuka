# Dependabot weekly updates (Cargo + GitHub Actions)

## Intent

Keep `Cargo.lock` (and GitHub Actions workflow dependencies) continuously updated via automated PRs so new RustSec advisories are addressed promptly and the existing security audit gate remains meaningful.

## Goals

- Enable Dependabot **version updates** for:
  - Rust dependencies (`cargo`) in the repository root (`/`)
  - GitHub Actions workflow dependencies (`github-actions`) in the repository root (`/`)
- Run updates on a **weekly** schedule.
- Reduce PR noise by **grouping** updates (one PR per ecosystem per week, when possible).

## Non-goals

- Auto-merge dependency PRs without human review.
- Changing audit policy or adding broad vulnerability exceptions.

## Constraints

- `Security Audit` job in `.github/workflows/ci.yml` (runs `python3 contrib/security/audit.py`) remains a required gate.
- No secrets or credentials are added to the repo.

## Acceptance criteria

- Repository contains a valid `.github/dependabot.yml` enabling weekly updates for `cargo` and `github-actions`.
- Dependabot opens PRs over time (next scheduled run) that update `Cargo.lock` and/or workflow action versions.
