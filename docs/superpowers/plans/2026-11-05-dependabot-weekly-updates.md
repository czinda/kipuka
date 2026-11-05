# Dependabot weekly updates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add weekly Dependabot PRs for Cargo dependencies and GitHub Actions so security advisories and dependency drift are handled continuously via reviewable PRs.

**Architecture:** Configure Dependabot via `.github/dependabot.yml` with two update entries (`cargo` and `github-actions`) at repository root, both scheduled weekly and grouped to reduce PR volume.

**Tech Stack:** GitHub Dependabot, GitHub Actions, Rust/Cargo lockfile updates.

**Spec:** `docs/superpowers/specs/2026-11-05-dependabot-weekly-updates-design.md`

## Global Constraints

- `Security Audit` job in `.github/workflows/ci.yml` (runs `python3 contrib/security/audit.py`) remains a required gate.
- Do not add secrets/credentials.

## Review Focus

- Dependabot config path and YAML structure are correct (`.github/dependabot.yml`, `version: 2`, `updates:` list).
- Schedule is weekly (not daily) for both ecosystems.
- Grouping is enabled to avoid excessive PR spam.
- No auto-merge behavior is introduced (that is a separate, explicit change).
- Cargo updates target `directory: "/"` so the workspace lockfile is updated.

---

### Task 1: Add Dependabot weekly config

**Files:**
- Create/Modify: `.github/dependabot.yml`

**Interfaces:**
- Consumes: N/A
- Produces: Weekly Dependabot PRs for `cargo` and `github-actions`.

- [ ] **Step 1: Update `.github/dependabot.yml`**

Ensure it contains two entries (Cargo + GitHub Actions) scheduled weekly and grouped.

- [ ] **Step 2: Sanity-check config formatting and location**

Run:

```bash
test -f .github/dependabot.yml
git diff -- .github/dependabot.yml
```

Expected: file exists and includes `package-ecosystem: cargo` and `package-ecosystem: github-actions`.

- [ ] **Step 3: Commit**

```bash
git add .github/dependabot.yml
git commit -m "chore: enable weekly dependabot updates"
```

---

## Verification

- [ ] Push the branch and confirm GitHub shows Dependabot enabled for the repo.
- [ ] Confirm PRs are created on the weekly schedule.
