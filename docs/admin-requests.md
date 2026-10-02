# Admin requests

Some of what the demo needs is not the engineer's to do. A project admin can run the whole
demo, but creating the project, changing its screens and workflow, licensing an agent,
allowing API tokens, opening an IP allowlist, and the Claude and Docker policies all belong to
someone with more rights. Each section below is one request, written to be forwarded as it
stands: fill in the `<...>` parts, and send only the ones that apply.

You rarely have to guess which. `configure`, `doctor` and `verify` end a line with
`; ask: docs/admin-requests.md#<anchor>` when one of these fixes what they found, and each
section says which check that is. Before asking, it is worth running
`python3 -m grafana_jsm_sandbox.doctor --only host,env,jira,facts`, so the request names what
Jira actually said.

The placeholders: `<KEY>` is the project key you want (two to ten capitals, digits or `_`,
starting with a letter), `<name>` its name, `<email>` the Atlassian account in `.env`, and
`<site>` your Jira site, `https://<your-site>.atlassian.net`.

## Jira admin: create project

For a Jira administrator (the global Administer Jira permission).

```text
Could you create a Jira Service Management project for a demo I am rehearsing?

- Template: IT service management, created from the Jira UI (Projects, Create project),
  company-managed.
- Key: <KEY>. Name: <name>.
- Please add me (<email>) to the project's Administrators role.

It is a sandbox: the demo creates, comments on and resolves test Incidents in it, and a reset
between rehearsals resolves and closes them. It needs no Premium features, and nothing else on
the site is touched.
```

Why an admin: creating a project needs Administer Jira, which a project admin does not hold.
The UI template is the reliable route; the project template key the REST API's published enum
offers for it fails, and the key that works is not in that enum (ADR 0004's amendment). The
demo needs its own project because the reset closes every open Incident carrying an `fp-`
label, and the queue has to start empty.

How the repo notices: `configure` and `doctor`'s `project` check fails when Jira has no project
`<KEY>` the account can see, or when it is not a Jira Service Management project; `issue type`
fails when it offers no Incident type, and `service desk` when it is no service desk the account
can see. Atlassian's guide:
<https://support.atlassian.com/jira-service-management-cloud/docs/create-a-service-project/>.

## Jira admin: Incident fields

For a Jira administrator, or a project admin where the project's screens are its own.

```text
On the Jira Service Management project <KEY>, could you check the create screen of the
Incident issue type?

- Severity, offering Sev-1, Sev-2 and Sev-3
- Urgency, offering Critical, High and Medium
- Source, offering "Monitoring systems"
- Labels and Description
- and no other field required unless it has a default value

The IT service management template normally brings all of these.
```

Why: a Run writes exactly those values, so it needs each field by that name offering those
options, and every Incident it creates carries a label and a description. Severity, Urgency and
Source are optional: when one is missing, has a twin of the same name, or lacks an option,
`configure` leaves its id empty in `.env` and a Run leaves the field off, so the demo runs and
its Incidents lack that field. Labels and Description are not optional, and nor is a screen
free of fields a Run cannot fill: without them every create is refused.

How the repo notices: `configure` and `doctor` read the project's own create metadata for the
Incident type, never the site's field list. A missing or ambiguous Severity, Urgency or Source,
or one lacking an option, is a WARN on the `severity`, `urgency` or `source` line naming this
request. A missing Labels or Description, or a required field with no default that no Run
fills, is a FAIL on `create screen`.

## Jira admin: Resolution screen

For a Jira administrator.

```text
On the Jira Service Management project <KEY>, could you put the Resolution field on the screen
of the Incident workflow's Resolve transition (the one to Completed), and keep the resolution
named Done on the site and available to that transition?

A Run completes each Incident by sending resolution Done with the transition. Today the screen
refuses it. If the workflow also sets Done in a post function, please leave that as it is.

An Incident completed without a resolution stays in the Incidents queue, because the queue
lists unresolved Incidents.
```

Why: a Run and the reset both complete an Incident with resolution Done. When the Resolve screen
has no Resolution field, Jira answers the transition with HTTP 400, and jira-as 2.0.0 quietly
retries it without a resolution. The retry succeeds (204) and the Incident reaches Completed. It
ends with resolution Done only if a workflow post function happens to set one, and otherwise
with none, so it stays in the queue.

What the presenter sees until it is done: on every close, the log shows a WARNING
`forwarded POST … upstream said 400` on the transition, then the retry, `upstream said 204`.
The warning looks like a failure during a demo, and it is the screen refusing, not the Run. The
Incident still completes. What matters is the Incident's last state, which the Run reads after
the transition: with a post function that sets Done the Run finishes normally, and without one it
ends `failed:` and the log shows `[FAILED] run reported failed: …`, naming the missing
resolution. Expect the 400 and say what it is, or ask for this before the day.

How the repo notices: `configure` and `doctor`'s `resolution` check fails when the site has no
Done. Whether the screen takes it shows only when an Incident is completed: the Run's own check
ends it `failed:` when the Incident is Completed with no resolution, `verify`'s `completed`
stage fails, naming this request, for the same Incident, and `reset` leaves such an Incident on
Completed, saying to ask for this, and takes it out on the next run once the screen is fixed. Once
the screen has the field, the transition succeeds on its first POST and the 400 is gone.

## Jira admin: workflow statuses

For a Jira administrator.

```text
On the Jira Service Management project <KEY>, could you check that the Incident workflow has
an initial status, an in progress status and a done status, with the first two outside the
Done category and the done status in it? A final close status in Done is optional.
```

Why: a Run moves an Incident through the roles in `DEMO_STATUS_OPEN`,
`DEMO_STATUS_IN_PROGRESS` and `DEMO_STATUS_DONE`; the reset also uses `DEMO_STATUS_CLOSED`
when it is nonempty. The defaults are Open, Work in progress, Completed and Closed.
`configure --write` discovers names from the project's workflow; set them by hand when it
cannot propose an unambiguous role. An empty `DEMO_STATUS_CLOSED` means no close step.
A Run finds the open Incident with `statusCategory != Done`, so the categories matter as
much as the names.

How the repo notices: `configure`'s `statuses` check proposes names or fails with the role and
available statuses. `doctor` validates the configured names and names the variable to fix.

## Jira admin: permissions

For a Jira administrator, or the project's administrator.

```text
On the Jira Service Management project <KEY>, could my account (<email>) have these
permissions: Browse projects, Create issues, Edit issues, Transition issues, Resolve issues,
Close issues and Add comments? The project's Administrators role normally carries them.

Delete issues as well would help, but is optional: it is only for removing an Incident that
ends up stuck in the queue.
```

Why: those are what a Run and the reset do on the project, with the account in `.env`. Without a
Jira Service Management agent licence the account lacks them whatever its role (the next
section).

How the repo notices: `configure` and `doctor`'s `permissions` check fails naming each one
missing, and warns for Administer projects and Delete issues. A `project` check that finds no
project `<KEY>`, and a 403 from Jira, name this request too.

## Atlassian org admin: agent licence

For an organization admin of the Atlassian organization that owns the site.

```text
Could my Atlassian account (<email>) have a Jira Service Management agent licence on <site>?
I need to work Incidents in the project <KEY> for a demo.
```

Why: only an agent can create and work Incidents in a service project. A project admin can add
an agent who is already licensed, but only an org admin can license one.

How the repo notices: the same `permissions` failure as above, a `service desk` check that
finds no service desk the account can see, and a 403 from Jira. `doctor`'s `whoami` names this
request when the account is deactivated.

## Atlassian org admin: API tokens

For an organization admin.

```text
Does the authentication policy that covers my account (<email>) let me create and use API
tokens for Jira on <site>, and what is the longest expiry it allows?

If API tokens are blocked for my account, could you instead create a service account with
Jira Service Management access, give it a scoped API token with the read:jira-work and
write:jira-work scopes, and add it to the Administrators role of the project <KEY>?
```

Why: the demo's Forwarder calls Jira with a token for that account, and the laptop helpers use
the same one. A service account's scoped token goes through the API gateway, so its
`JIRA_SITE_URL` is `https://api.atlassian.com/ex/jira/<cloudId>` (`.env.example` says where the
cloud id comes from); `doctor` accepts either form. Whether a scoped token also needs a Jira
Service Management scope for `configure`'s service desk and queue reads has not been tried.
Tokens expire, after one to 365 days as the policy allows: note the date.

How the repo notices: a 401 on the first Jira call, from `configure` or `doctor`'s `jira`
layer on the laptop, or from the container's own check in `doctor`'s `stack` layer. Before
asking, open <https://id.atlassian.com/manage-profile/security/api-tokens>: a create button you
cannot use means the policy blocks you. Atlassian's pages:
<https://support.atlassian.com/security-and-access-policies/docs/understand-authentication-policies/>
and
<https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/>.

## Atlassian org admin: IP allowlist

For an organization admin, when the site's IP allowlist is on.

```text
<site> refuses my requests with an IP allowlist error. Could you allowlist the address my
laptop reaches it from (<address>), or tell me which VPN to connect through, for the days I
rehearse and give a demo? Both my laptop's tools and a Docker container on it call the Jira
REST API.
```

Why: the Forwarder in the demo container and the laptop helpers both call the site from the
laptop's network, and an allowlist refuses them before any credential is looked at.

How the repo notices: a 403 whose body reads like an IP-allowlist refusal, from `configure` and
`doctor`'s `jira` layer on the laptop and from the container's own check in `doctor`'s `stack`
layer; in the container log it is a WARNING `forwarded ... upstream said 403` line saying so.
Atlassian's page:
<https://support.atlassian.com/security-and-access-policies/docs/specify-ip-addresses-for-product-access/>.

## Claude org owner

For an Owner of the Claude organization your seat belongs to.

```text
I am running a demo in which Claude Code runs headless, in print mode, inside a Docker
container on my laptop, and I would like to check four things for my seat (<your Claude
account>):

1. May I run `claude setup-token` and use the token it prints for Claude Code, choosing our
   organization on the consent screen? (If login is forced to another method, it may not.)
2. Do our managed settings set allowManagedPermissionRulesOnly? The demo depends on Claude
   Code's own --allowedTools list, which that setting drops.
3. Do they pin Claude Code to a version range that excludes 2.1.272, the version in the
   demo's image?
4. If they restrict availableModels, is claude-opus-5 on the list? If not, which model may
   I use?

Also: do my usage credits, or my spend cap, cover a few dollars of runs on a rehearsal day,
and does our data policy allow sending alert details and Jira issue text to Claude from a
local container?
```

Why: a Run authenticates with the token `claude setup-token` prints, and its only permissions
are the allow list the Receiver passes on its command line. Each Run asks for `RUN_MODEL`,
`claude-opus-5` unless `.env` names another. A lifecycle is three Runs and about $1.15 on
Opus 5 (measured 2026-09-24), plus about $0.12 for one `doctor --with-model`.

How the repo notices: `doctor`'s `env` layer names this request when `.env` holds no Claude
token. `doctor --with-model` starts one short, real Run in the container and names it when an
allowed call was denied, which only managed rules can do, or when the Run failed for want of
credits or a model the seat may not use; the log's `[FAILED]` and `[hint]` lines say the same
for a live Run. Claude Code's pages: <https://code.claude.com/docs/en/authentication> and
<https://code.claude.com/docs/en/managed-settings>.

## Docker admin

For whoever administers Docker Desktop in your organization, when its policy restricts images.

```text
For a demo I run with Docker Compose on my laptop, could Docker Desktop pull these images from
Docker Hub, or could you tell me the internal mirror that carries them?

- grafana/otel-lgtm:0.33.0 (a Verified Publisher image)
- node:24.21.0-trixie-slim, python:3.13-slim and alpine:3.20 (Docker Official Images)

The build also installs packages from registry.npmjs.org, pypi.org and deb.debian.org.
If Enhanced Container Isolation is enforced on my machine, please tell me, so I can put any
failure in the demo's container checks down to it.
```

Why: `docker compose up -d --build` pulls two images and builds two on top of base images.
The pulled ones are the Grafana stack, which `LGTM_IMAGE` in `.env` can point at a mirror's
copy, and `alpine:3.20` for the traffic service, which `docker-compose.yml` names with no
variable. The bases are `node` for the demo image, which the `BASE_IMAGE` build argument of
the top-level `Dockerfile` can replace, and `python:3.13-slim` for rolldice, named in
`docker/rolldice/Dockerfile`. A registry mirror in Docker Desktop's own settings covers
whatever has no such knob. Kubernetes does not need to be enabled.

How the repo notices: `doctor`'s `host` layer warns, naming this request, when an image compose
pulls is not on the machine yet; a pull refused by policy then fails in `docker compose up`
itself.

## Network

Not a request to one person, but worth checking before the day. The laptop, and Docker on it,
reach `<site>` (or `api.atlassian.com`) and `api.anthropic.com` while the demo runs, and
Docker Hub, `registry.npmjs.org`, `pypi.org` with `files.pythonhosted.org`, and
`deb.debian.org` while it builds. `pip install -e '.[dev]'` for the tests needs a package index
too; behind a registry mirror, point pip at it. A laptop behind an intercepting proxy needs the
corporate root CA, which [the runbook](demo-runbook.md#on-the-work-laptop-the-corporate-ca)
covers.
