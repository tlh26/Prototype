# Evidence Agent

`evidenceAgent` is a lightweight Python evidence-collection and delivery service for cloud instances and their underlying Incus host.

The package provides two complementary collection modes:

* **Instance Agent** — collects evidence generated inside an individual instance, including authentication, web-access, and file-activity evidence.
* **Host Evidence Agent** — incrementally collects and attributes host-level `auditd` events to Incus projects and instances.

Both agents use local persistent spooling so that evidence is not lost when the Central Evidence API is temporarily unavailable. Evidence is delivered to the Central API only after successful transmission and acknowledgement.

## Architecture

```text
                         Incus Host
                              |
                 +------------+------------+
                 |                         |
          Host auditd                  Incus instances
          /var/log/audit/              +-----------+
                 |                     |           |
                 v                   web-01      api-01
        Host Evidence Agent             |           |
                 |                       |           |
                 |                 Instance Agent  Instance Agent
                 |                       |           |
                 +-----------+-----------+-----------+
                             |
                      Local persistent
                          spool
                             |
                             v
                    Central Evidence API
                             |
                             v
                    Central evidence DB
```

The two collection paths serve different evidence sources:

| Agent               | Execution context        | Primary evidence                                       |
| ------------------- | ------------------------ | ------------------------------------------------------ |
| Instance Agent      | Inside an Incus instance | Authentication, web access, watched-file activity      |
| Host Evidence Agent | Incus host               | `auditd` events attributed to Incus projects/instances |

The agents are complementary rather than alternatives. Instance-level collection provides evidence directly observable within a tenant instance, while host-level collection provides platform-level evidence that can be attributed back to the relevant tenant and instance.

## Features

### Instance evidence collection

* Collects authentication events from a configurable authentication log.
* Collects access events from a configurable access log.
* Watches a configurable directory for file evidence.
* Produces deterministic evidence identifiers.
* Associates evidence with the configured tenant and instance.
* Persists pending evidence locally before transmission.

### Host audit collection

* Reads the host `auditd` log incrementally.
* Maintains a persistent checkpoint to avoid repeatedly processing the same audit log data.
* Groups related `auditd` records into logical audit events.
* Attributes Incus audit subjects to the corresponding project and instance.
* Produces deterministic host event identifiers.
* Persists host evidence batches locally before transmission.
* Supports recovery after interruption or Central API outages.

### Reliable delivery

* Uses a persistent local spool for undelivered evidence.
* Retries delivery during subsequent collection cycles.
* Removes spooled evidence only after successful Central acknowledgement.
* Supports operation during temporary Central API or network outages.
* Handles `SIGINT` and `SIGTERM` for graceful shutdown.

## Evidence delivery

Instance evidence is submitted to:

```text
POST /api/v1/evidence/events
```

Host audit evidence is submitted as batches to:

```text
POST /api/v1/evidence/batches
```

The Central API is responsible for authoritative persistence of received evidence.

The local spool acts as a delivery buffer rather than the authoritative evidence store.

```text
Collect
   |
   v
Create evidence
   |
   v
Persist to local spool
   |
   v
Attempt Central delivery
   |
   +---- success ----> Central acknowledgement
   |                         |
   |                         v
   |                  Remove spool item
   |
   +---- failure ----> Keep spool item
                             |
                             v
                       Retry later
```

This design allows evidence collection to continue when Central is temporarily unavailable without silently discarding collected evidence.

## Requirements

* Python 3.10 or newer.
* A reachable Central Evidence API.
* A valid API key for the Central API.
* Read access to the logs and directories being collected.
* For host mode:

  * access to the host `auditd` log;
  * Incus audit-subject information for attribution;
  * appropriate privileges to read the audit log.

The normal instance agent does **not** require the wider `Prototype` repository to be installed.

Host-agent functionality depends on the host-audit acquisition components packaged with the deployment.

## Installation

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the package:

```bash
python -m pip install -e evidenceAgent
```

The package provides the:

```bash
evidence-agent
```

command.

The module form is also supported:

```bash
python -m evidenceAgent.run
```

For a production deployment, install the built wheel instead:

```bash
python -m pip install evidence_agent-1.2.9-py3-none-any.whl
```

### Package naming

The project intentionally uses different names in different Python packaging
contexts:

| Purpose                | Name                | Example                       |
| ---------------------- | ------------------- | ----------------------------- |
| PyPI/distribution name | `evidence-agent`    | `pip install evidence-agent`  |
| Python import package  | `evidenceAgent`     | `import evidenceAgent`        |
| CLI command            | `evidence-agent`    | `evidence-agent`              |
| Module execution       | `evidenceAgent.run` | `python -m evidenceAgent.run` |

The distinction is intentional. The distribution name follows Python
packaging conventions and uses a hyphen, while the source package retains
the `evidenceAgent` name used by the implementation.

For example, after installation:

```bash
python -m pip install evidence_agent-1.2.9-py3-none-any.whl
```

the package can be imported with:

```python
import evidenceAgent
```

and the agent can be started with:

```bash
evidence-agent
```

The distribution name and import package name should therefore not be
treated as interchangeable.


## Configuration

### Common configuration

The following variables are used by the agent:

| Variable               | Description                                |
| ---------------------- | ------------------------------------------ |
| `EVIDENCE_TENANT_ID`   | Tenant associated with the evidence.       |
| `EVIDENCE_AGENT_ID`    | Unique identifier for the agent.           |
| `EVIDENCE_CENTRAL_URL` | Base URL of the Central Evidence API.      |
| `EVIDENCE_API_KEY`     | API key sent using the `X-API-Key` header. |
| `EVIDENCE_INTERVAL`    | Seconds between collection cycles.         |
| `EVIDENCE_LOG_LEVEL`   | Python logging level.                      |

For instance collection, the following variable is also required:

| Variable                 | Description                           |
| ------------------------ | ------------------------------------- |
| `EVIDENCE_INSTANCE_NAME` | Name of the instance being monitored. |

### Instance configuration

| Variable                     | Default                         | Description                            |
| ---------------------------- | ------------------------------- | -------------------------------------- |
| `EVIDENCE_AUTH_LOG`          | `/var/log/auth.log`             | Authentication log path.               |
| `EVIDENCE_ACCESS_LOG`        | `/var/log/nginx/access.log`     | Web access log path.                   |
| `EVIDENCE_WATCHED_DIRECTORY` | `/tmp/evidence`                 | Directory monitored for file evidence. |
| `EVIDENCE_STATE_DIRECTORY`   | `/var/lib/evidence-agent`       | Agent state directory.                 |
| `EVIDENCE_SPOOL_DIRECTORY`   | `/var/lib/evidence-agent/spool` | Instance evidence spool directory.     |
| `EVIDENCE_INTERVAL`          | `10`                            | Seconds between collection cycles.     |
| `EVIDENCE_LOG_LEVEL`         | `INFO`                          | Python logging level.                  |

Example:

```bash
export EVIDENCE_TENANT_ID="tenant-b"
export EVIDENCE_INSTANCE_NAME="web-b"
export EVIDENCE_AGENT_ID="agent-web-b"

export EVIDENCE_CENTRAL_URL="http://192.168.64.18:9443"
export EVIDENCE_API_KEY="replace-me"

export EVIDENCE_AUTH_LOG="/var/log/auth.log"
export EVIDENCE_ACCESS_LOG="/var/log/nginx/access.log"
export EVIDENCE_WATCHED_DIRECTORY="/tmp/evidence"

export EVIDENCE_STATE_DIRECTORY="/var/lib/evidence-agent"
export EVIDENCE_SPOOL_DIRECTORY="/var/lib/evidence-agent/spool"

export EVIDENCE_INTERVAL="10"
export EVIDENCE_LOG_LEVEL="INFO"
```

## Host Evidence Agent

Host mode is disabled by default.

Enable it with:

```bash
export EVIDENCE_HOST_AGENT_ENABLED=true
```

Host mode uses the same Central API configuration as the Instance Agent.

| Variable                        | Default                                                | Description                             |
| ------------------------------- | ------------------------------------------------------ | --------------------------------------- |
| `EVIDENCE_HOST_AGENT_ENABLED`   | `false`                                                | Enables host audit collection.          |
| `EVIDENCE_AUDIT_PATH`           | `/var/log/audit/audit.log`                             | Host `auditd` log path.                 |
| `EVIDENCE_HOST_CHECKPOINT_PATH` | `$EVIDENCE_STATE_DIRECTORY/host-audit-checkpoint.json` | Persistent audit collection checkpoint. |
| `EVIDENCE_HOST_SPOOL_DIRECTORY` | `$EVIDENCE_STATE_DIRECTORY/host-spool`                 | Host evidence batch spool.              |
| `EVIDENCE_INTERVAL`             | `10`                                                   | Seconds between host collection cycles. |

The host agent requires access to:

```text
/var/log/audit/audit.log
```

This will normally require elevated privileges.

### Running host and instance agents together

The intended deployment is for both agents to operate collaboratively:

```bash
export EVIDENCE_HOST_AGENT_ENABLED=true
export EVIDENCE_INSTANCE_AGENT_ENABLED=true
```

The resulting process can collect:

```text
                    evidence-agent
                         |
              +----------+----------+
              |                     |
              v                     v
       Instance Agent       Host Evidence Agent
              |                     |
              v                     v
       instance evidence       auditd evidence
              |                     |
              +----------+----------+
                         |
                         v
                  Central Evidence API
```

If only host collection is required:

```bash
export EVIDENCE_HOST_AGENT_ENABLED=true
export EVIDENCE_INSTANCE_AGENT_ENABLED=false
```

If only instance collection is required:

```bash
export EVIDENCE_HOST_AGENT_ENABLED=false
export EVIDENCE_INSTANCE_AGENT_ENABLED=true
```

## Running

Activate the environment:

```bash
source .venv/bin/activate
```

Start the agent:

```bash
evidence-agent
```

or:

```bash
python -m evidenceAgent.run
```

The agent reports collection and delivery activity through the configured logging level.

If Central is unavailable, evidence remains in the appropriate local spool and is retried during subsequent delivery cycles.

## State and spool management

The agent maintains local state under:

```text
/var/lib/evidence-agent/
```

A typical deployment contains:

```text
/var/lib/evidence-agent/
├── spool/
│   └── <pending-instance-evidence>
├── host-spool/
│   └── <pending-host-batches>
└── host-audit-checkpoint.json
```

The host checkpoint records the position reached in the audit log so that collection can continue incrementally across agent restarts.

Spool contents should be treated as evidence and protected accordingly.

## systemd deployment

A systemd deployment example is provided in:

```text
deployment/agent/evidence-agent.service
```

An environment template is provided in:

```text
deployment/agent/agent.env.template
```

Before deploying:

1. Copy the environment template to the appropriate protected location.
2. Set the Central API URL and API key.
3. Configure tenant and instance identifiers.
4. Configure the required log paths.
5. Enable or disable host and instance collection as required.
6. Ensure the service account has the required permissions.

Reload systemd:

```bash
sudo systemctl daemon-reload
```

Enable and start the service:

```bash
sudo systemctl enable --now evidence-agent
```

View the service logs:

```bash
sudo journalctl -u evidence-agent -f
```

Check service status:

```bash
sudo systemctl status evidence-agent
```

## Development

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e evidenceAgent
```

Install development dependencies:

```bash
python -m pip install -r requirements.txt
```

Run the complete test suite:

```bash
pytest -q
```

Run only agent-related tests:

```bash
pytest -q tests/agent
```

Run acquisition tests:

```bash
pytest -q tests/acquisition
```

## Testing delivery recovery

The reliability model should be tested by deliberately making Central unavailable.

Expected behaviour:

```text
Agent
  |
  +--> Central unavailable
  |
  +--> Evidence remains in local spool
  |
  +--> Central becomes available
  |
  +--> Agent retries
  |
  +--> Central acknowledges
  |
  +--> Spool item is removed
```

A successful retry must not require recollecting the original evidence.

The Central database should also be checked to ensure that retrying an already acknowledged event does not create duplicate evidence records.

## Security considerations

* Keep `EVIDENCE_API_KEY` in a protected environment file or secret manager.
* Never commit API keys or other credentials to Git.
* Restrict permissions on state and spool directories.
* Treat spooled evidence as sensitive forensic data.
* Grant the agent only the permissions required to read its configured evidence sources.
* Host audit collection should run with the minimum privileges necessary to read the audit log.
* Protect communication with Central using HTTPS in production.
* Do not expose the Central API or agent management interfaces unnecessarily.
* Ensure tenant and instance identifiers are configured correctly before deployment.

## Operational model

The agent is designed for deployment across multiple Incus tenants and instances.

For example:

```text
Incus Host
│
├── Project: tenant-a
│   ├── web-a  → Instance Agent
│   ├── api-a  → Instance Agent
│   └── db-a   → Instance Agent
│
├── Project: tenant-b
│   ├── web-b  → Instance Agent
│   ├── api-b  → Instance Agent
│   └── db-b   → Instance Agent
│
└── Host
    └── Host Evidence Agent
             |
             +--> auditd
             |
             +--> Incus attribution
             |
             +--> Central Evidence API
```

This allows the Central service to receive evidence from both the **tenant/instance perspective** and the **cloud-platform/host perspective**.

## Project role

`evidenceAgent` forms the acquisition and delivery layer of the evidence-processing prototype.

Its responsibility is to:

1. Acquire evidence from configured sources.
2. Preserve evidence locally until delivery succeeds.
3. Associate evidence with its tenant and execution context.
4. Deliver evidence to the Central Evidence API.
5. Recover from temporary delivery failures.

Correlation, analysis, and higher-level evidence relationships are performed by downstream components of the wider prototype rather than by the agent itself.
