# AGENTS.md — Application Workspace: `dns-pinger`

## 1. Workspace Scope & Isolation Boundaries
- **Scope**: Application source code (`dnspython-pinger.py`, `requirements.txt`), example configurations (`config/*.example`), `Dockerfile`, `docker-compose.yaml`, and Gitea CI/CD image build workflows (`.gitea/workflows/build.yaml`).
- **Workspace Boundary (STRICT)**:
  - You are strictly confined to `/home/sheldon/infra/apps/dns-pinger`.
  - **NEVER** ascend into parent directories (`..`) or read, modify, or execute files in `/home/sheldon/infra/ansible-infrastructure`, `/home/sheldon/infra/roles/*`, or any other workspace outside this root.
  - Production deployment of the built container image (`gitea.home.cole.casa/sheldon-cole/dns-pinger`) is managed externally by the `core-services-deploy` Ansible role.

## 2. Zero-Trust Secret & Vault Policy (CRITICAL)
- **Zero Secret Access**: You must **NEVER** read, `cat`, `grep`, parse, or output the contents of `.env`, `**/vault.yml`, `*vault*`, `*.key`, `*.pem`, or any live rule configuration files containing API tokens or passwords—either via file-reading tools or shell commands.
- When adding or modifying environment variables or rule options, document them exclusively in `README.md`, `docker-compose.yaml` (using `<placeholder>` syntax), `config/hostinger-config.yaml.example`, and `config/pangolin-config.yaml.example`.
