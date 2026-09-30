# grafana-jsm-sandbox

Grafana alert Notification -> sandboxed Claude Run -> Jira Service Management Incident. See `README.md` for what the demo is and needs. `skill/incident-sync/SKILL.md` is the Run's Skill as a template: the Receiver renders it from the demo's configuration (`.env`, which compose hands the container) into `<runs directory>/.skill`, and the site facts in `.env` come from `python3 -m grafana_jsm_sandbox.configure`. How Incidents are matched and managed is `docs/adr/0004-fingerprint-label-and-platform-ops-only.md`.

Setting the demo up on an engineer's site: follow the setup skill in `.claude/skills/demo-setup/`, which is not the Run's Skill. `python3 -m pytest --basic-demo` runs chapter one's tests alone.

## Agent skills

### Issue tracker

Issues live as local markdown under `.scratch/<feature>/`, which is git-ignored: working notes are never published. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: needs-triage, needs-info, ready-for-agent, ready-for-human, wontfix. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
