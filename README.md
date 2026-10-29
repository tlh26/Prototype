# Multi-Tenant Evidence Correlation Dashboard for South African Government Clouds

Prototype implemented the framework proposed in this research, which collects, securely store, and analyse evidence from cloud instances and their underlying Incus hosts. Evidence is associated with tenants and instances, delivered to a central API, and presented through a Django dashboard with correlation, timeline, and privacy controls.

> **Status:** Prototype for research and evaluation. Review deployment, authentication, privacy, and operational requirements before using with production or sensitive data.

## What it does

- **Collects instance evidence** such as authentication, web-access, and watched-file activity.
- **Collects host audit evidence** from `auditd` and attributes events to Incus projects and instances.
- **Buffers evidence locally** so collection can continue during temporary network or Central API outages.
- **Verifies evidence integrity** using SHA-256 hashes.
- **Stores evidence centrally** in PostgreSQL through a FastAPI service.
- **Displays evidence and analysis** in a Django dashboard, including overview, evidence, correlations, tenants, and timelines.
- **Supports correlation privacy modes**: `raw`, `pseudonymised`, `generalised`, and `restricted`.

## Architecture

```text
Instance agents ───────┐
                       ├──> Local persistent spool ──> Central Evidence API ──> PostgreSQL
Incus host agent ──────┘                                                        │
                                                                               v
                                                               Django dashboard and
                                                               correlation engine
```

The agents’ local spool is a delivery buffer; Central PostgreSQL is the authoritative evidence store. The dashboard reads evidence from Central PostgreSQL.

## Main components

| Path | Purpose |
| --- | --- |
| `evidenceAgent/` | Python evidence-agent package and collection/delivery logic |
| `acquisition/` | Evidence acquisition services and collectors |
| `central/` | FastAPI Central API, PostgreSQL access, and evidence ingestion |
| `correlation/` | Evidence normalization, candidate generation, correlation, and privacy controls |
| `dashboard/` | Django dashboard pages and services |
| `evidence/`, `processing/`, `storage/` | Evidence models, processing, and storage helpers |
| `deployment/` | Agent service and deployment scripts |
| `tests/` | Automated tests |
| `Architecture/` | Architecture diagrams and related documentation |

## Requirements

- Python compatible with the pinned dependencies in `requirements.txt`.
- PostgreSQL for the Central Evidence API and dashboard evidence source.
- For agent deployment: access to the relevant logs and files; host collection also requires suitable access to `auditd` and Incus information.
- Incus is required if using the provided Incus deployment workflow.

The standalone agent package requires Python 3.10 or newer. See [`evidenceAgent/ReadMe.md`](./evidenceAgent/ReadMe.md) for agent-specific setup and configuration details.

## Experimental environment

The following describes the environment recorded for the prototype evaluation, not a minimum or recommended production configuration. Host resource values are point-in-time measurements captured with the experiment metadata.

| Area | Recorded configuration |
| --- | --- |
| Experiment host | Ubuntu 24.04.4 LTS guest VM, hostname `tood-Virtual-Machine`, on `aarch64`; recorded kernel `7.0.0-31-generic`. |
| CPU | CPU model, number of cores, and VM vCPU allocation were not recorded. |
| Memory | Approximately 3.8 GiB total RAM; the baseline snapshot reports approximately 2.5 GiB available and 4.0 GiB swap. |
| Storage | Root filesystem on `/dev/vda2`, 68 GiB total, with 43 GiB used and 22 GiB available in the captured baseline. Incus used a `dir` storage pool at `/var/lib/incus/storage-pools/local`. Physical disk type and underlying host storage configuration were not recorded. |
| Virtualisation | Incus client and server version 6.0.0 ran on the Ubuntu VM. The recorded Incus inventory contains 17 containers across five projects (the default project and four tenant projects); 15 were running and two were stopped in that snapshot. Incus container CPU and memory limits were not recorded. |
| Language/runtime | Python 3.12.3 on the experiment host. The separately packaged evidence agent declares Python 3.10 or newer as its minimum. |
| Application framework | Django 6.1.1; FastAPI 0.141.1 and Uvicorn 0.52.4 for the Central Evidence API. |
| Database client and server | The pinned Python PostgreSQL driver is Psycopg 3.3.6. Experiment history configures the Central PostgreSQL database through a remote private-network endpoint on port 5432. The PostgreSQL server version and the database host's CPU, RAM, storage, and physical-versus-VM configuration were not recorded. |
| Correlation dependencies | The correlation implementation primarily uses the Python standard library (including `bisect`, `collections`, `datetime`, `hashlib`, and `hmac`) and Pydantic 2.13.4 for data models and validation. Psycopg 3.3.6 is used for Central database access; it is not the correlation scoring library. |

The host OS, Incus, Python, memory, disk, and container values are from the captured experiment configuration and `RUN_001` metadata. Application dependency versions are those pinned in [`requirements.txt`](./requirements.txt); they describe the recorded project dependency set, not independently verified versions of every service installed on the separate database host. See [`experimentation/configs/`](./experimentation/configs/), [`experimentation/results/RUN_001/metadata/`](./experimentation/results/RUN_001/metadata/), and [`experimentation/exported_history.txt`](./experimentation/exported_history.txt) for the underlying records. Missing CPU and PostgreSQL host details should be treated as unreported, not assumed.

## Getting started

### 1. Clone and install dependencies

```bash
git clone https://github.com/tlh26/Prototype.git
cd Prototype

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 2. Configure the Central API

Set the PostgreSQL connection string and API key in your shell or a protected environment file:

```bash
export CENTRAL_DATABASE_URL="postgresql://USER:PASSWORD@HOST:5432/DATABASE"
export EVIDENCE_API_KEY="replace-with-a-secret-value"
```

Do not commit real credentials or secrets to the repository. The API requires `CENTRAL_DATABASE_URL` at startup. The application creates its evidence tables and indexes if they do not already exist.

Start the API:

```bash
python -m uvicorn central.app:app --host 127.0.0.1 --port 9443
```

The health endpoint is available at `http://127.0.0.1:9443/health`. FastAPI’s interactive API documentation is available at `http://127.0.0.1:9443/docs`.

### 3. Configure and start the dashboard

In a second terminal, activate the virtual environment and set a Django secret key and the same PostgreSQL connection string:

```bash
source .venv/bin/activate

export CENTRAL_DATABASE_URL="postgresql://USER:PASSWORD@HOST:5432/DATABASE"
export DJANGO_SECRET_KEY="replace-with-a-stable-secret-of-at-least-32-bytes"
export CORRELATION_PRIVACY_MODE="pseudonymised"

python manage.py runserver
```

Open `http://127.0.0.1:8000/`.

Available dashboard pages include:

- `/` — overview
- `/evidence/` — evidence list
- `/correlations/` — correlation analysis
- `/timeline/` — evidence timeline
- `/tenants/` — tenant view

For local development, Django’s settings use SQLite for Django-managed data. Evidence displayed in the dashboard is read from the Central PostgreSQL database.

## Evidence agent

The agent supports instance-level collection and host-level audit collection. It persists pending evidence locally and retries delivery until Central acknowledges it.

For standalone package installation, environment variables, and collection configuration, see [`evidenceAgent/ReadMe.md`](./evidenceAgent/ReadMe.md). The repository also includes an environment template at [`deployment/agent/agent.env.template`](./deployment/agent/agent.env.template) and an Incus deployment script at [`deployment/scripts/deployAgent.sh`](./deployment/scripts/deployAgent.sh).

Protect the agent’s environment file: it contains the API key. Use a unique agent ID and configure tenant and instance identifiers for the deployment.

## Privacy modes

Set `CORRELATION_PRIVACY_MODE` to one of:

- `raw` — use untransformed evidence for analysis. This is the default.
- `pseudonymised` — replace selected identifiers with stable, field-scoped HMAC tokens.
- `generalised` — reduce detail in selected values, such as timestamps, network addresses, and paths.
- `restricted` — limit the feature types available to correlation and analysis.

Privacy modes affect the dashboard’s analytical projection; they do not rewrite the authoritative evidence in PostgreSQL. In `raw` mode, the dashboard can display raw evidence details. Choose a mode appropriate to your data and access requirements. See [`correlation/README.md`](./correlation/README.md) for details.

## Configuration reference

| Variable | Used by | Purpose |
| --- | --- | --- |
| `CENTRAL_DATABASE_URL` | Central API and dashboard | PostgreSQL connection string |
| `EVIDENCE_API_KEY` | Central API and agents | API authentication key |
| `CENTRAL_HOST` | Central API | Bind address; defaults to `0.0.0.0` |
| `CENTRAL_PORT` | Central API | Port setting; defaults to `9443` |
| `DJANGO_SECRET_KEY` | Dashboard | Django signing key and pseudonymisation key |
| `CORRELATION_PRIVACY_MODE` | Dashboard | Correlation privacy mode; defaults to `raw` |
| `CORRELATION_PERMITTED_FEATURE_TYPES` | Dashboard | Optional comma-separated allowlist for `restricted` mode |
| `DASHBOARD_EVIDENCE_LIMIT` | Dashboard | Maximum evidence records used by dashboard analysis |
| `DASHBOARD_RULE_WINDOW_SECONDS` | Dashboard | Temporal correlation window |

Agent-specific variables are documented in [`evidenceAgent/ReadMe.md`](./evidenceAgent/ReadMe.md).

## Running tests

Run the project test suite from the repository root:

```bash
python -m pytest
```

## Security notes

- Replace all example credentials and keys with securely managed values.
- Do not expose the Central API publicly without appropriate network controls and deployment hardening.
- Use a stable, secret `DJANGO_SECRET_KEY` of at least 32 bytes when using pseudonymised mode.
- The default correlation mode is `raw`; select a privacy mode intentionally when handling sensitive evidence.
- Review agent privileges and file access before deploying collectors.

## License

See [`LICENSE`](./LICENSE).
