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

This table documents the captured prototype evaluation environment, not a production sizing recommendation. Host resource readings are point-in-time snapshots; package versions are the versions pinned in the repository dependency file.

| Layer | Component | Recorded configuration |
| --- | --- | --- |
| Application/Incus VM | Operating system and architecture | Ubuntu 24.04.4 LTS (Noble), `aarch64`; captured kernel `7.0.0-31-generic`. |
| Application/Incus VM | CPU | CPU model, vCPU count, and physical host CPU allocation were not captured. |
| Application/Incus VM | Memory | Approximately 3.8 GiB RAM; snapshot shows approximately 2.5 GiB available and 4.0 GiB swap. |
| Application/Incus VM | Storage | Guest root filesystem: 68 GiB total, 43 GiB used, 22 GiB available in the captured snapshot. Incus storage pool uses the `dir` driver. Underlying physical disk, IOPS, and host storage allocation are unreported. |
| Application/Incus VM | Virtualization | Incus client and server 6.0.0. Snapshot inventory: 17 containers across the default project and four tenant projects; 15 running and two stopped. Per-container resource limits and the underlying hypervisor configuration were not captured. |
| Application/Incus VM | Python runtime | Python 3.12.3 in the experiment capture. The standalone agent package declares Python 3.10 or newer. |
| Application/Incus VM | Application services | Django 6.1.1 dashboard; FastAPI 0.141.1 Central API served by Uvicorn 0.52.4. |
| Application/Incus VM | Main correlation / data dependencies | Pydantic 2.13.4, Psycopg 3.3.6, and Python standard-library modules including `bisect`, `collections`, `datetime`, `hashlib`, and `hmac`. |
| Application/Incus VM | Dashboard-managed database | SQLite is configured for Django-managed data. Evidence and correlation inputs are read from Central PostgreSQL. |
| Separate database machine | PostgreSQL server | Experiment history shows the Central database configured at a remote private-network endpoint on TCP port 5432. The server version, operating system, CPU, RAM, storage, virtualization type, and PostgreSQL tuning settings were not recorded. No address or credentials are reproduced here. |

### Deployment arrangement and communication

The captured setup uses an Ubuntu guest VM as the application and Incus host. The Central Evidence API and Django dashboard run from this project’s Python environment on that VM; Incus hosts the tenant workload containers. Instance agents run in configured workloads, while the host audit agent reads the Incus host's `auditd` log. Central PostgreSQL is on a separate machine, reached by the API and dashboard over the configured private network. The experiment records do not specify which physical or virtual infrastructure hosts that database machine.

Agents communicate with Central using HTTP JSON REST requests through the configured `EVIDENCE_CENTRAL_URL`. Instance events use `POST /api/v1/evidence/events`; host audit data is sent in batches to `POST /api/v1/evidence/batches`. Requests carry an API key in the `X-API-Key` header, and raw evidence bytes are Base64-encoded for JSON transport. The Central API and dashboard connect to PostgreSQL using Psycopg (PostgreSQL's client protocol). Django uses its local SQLite database for Django-managed data. The agent client accepts an HTTP or HTTPS URL; it does not itself enforce TLS. The deployment must therefore provide transport protection (for example, HTTPS/TLS termination and network controls) rather than assuming it is enabled by the code.

### Starting, configuring, securing, and monitoring

- **Central API:** Configure `CENTRAL_DATABASE_URL` and `EVIDENCE_API_KEY` through the process environment or a protected environment file. Start for local development with `python -m uvicorn central.app:app --host 127.0.0.1 --port 9443`. The API configuration defaults to host `0.0.0.0` and port `9443` when deployed through its configured runtime; bind only to an intended interface and apply firewall/reverse-proxy controls.
- **Dashboard:** Configure `CENTRAL_DATABASE_URL`, `DJANGO_SECRET_KEY`, and, as needed, `CORRELATION_PRIVACY_MODE` and `CORRELATION_PERMITTED_FEATURE_TYPES`. `DJANGO_SECRET_KEY` signs Django data and is also passed to the correlation engine for pseudonymisation/generalisation. Keep it stable, secret, and out of source control. The `python manage.py runserver` command documented here is for development, not production deployment.
- **Agents:** Provide tenant, instance (instance agent), and agent identifiers, Central URL, and API key through a protected environment file. Defaults include a 10-second collection interval and local state/spool directories; host mode also configures the audit-log and checkpoint paths. The supplied systemd unit starts the agent as root, restarts it after failures, and sends standard output/error to the system journal. Protect the file because it contains the API key; grant only required log access and privileges.
- **Security boundary:** The API checks the API key and verifies the SHA-256 digest of submitted evidence before storage. These controls do not by themselves encrypt network traffic, provide per-user tenant access control, or make database records tamper-proof. Use TLS, restricted network reachability, secure secret management, and least-privilege deployment as operational controls. Do not expose credentials, internal endpoint addresses, or secret values in reports.
- **Monitoring:** The API exposes `GET /health` for service/database status. Agent service output is available in systemd's journal; API and development dashboard output is emitted by their service processes. The correlation service logs timing and event/candidate/finding counts. The repository does not configure a central metrics, alerting, tracing, or log-retention stack, so availability beyond these endpoints and logs is not claimed.

The recorded environment facts come from [`experimentation/configs/`](./experimentation/configs/) and [`experimentation/results/RUN_001/metadata/`](./experimentation/results/RUN_001/metadata/); the remote database arrangement is reflected in [`experimentation/exported_history.txt`](./experimentation/exported_history.txt). Software versions are pinned in [`requirements.txt`](./requirements.txt). CPU allocation and the separate PostgreSQL machine's detailed configuration remain unreported; they should not be inferred from the VM snapshot.

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
