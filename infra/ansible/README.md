# Ansible — Proxmox provisioning

Manages VMs (and later LXC) on a single Proxmox cluster (two nodes:
`pve-node1`, `pve-node2`).

## Layout
- `inventory/hosts.yml` — one connection target for the cluster API.
- `inventory/group_vars/proxmox.yml` — API endpoint, token, and the VM list.
- `inventory/group_vars/all.yml` — shared VM defaults.
- `roles/proxmox_vm/` — role that creates the VMs.
- `playbooks/provision-vms.yml` — entrypoint.

Which node a VM lands on is set by the `node:` field on each VM entry.

## Setup
```bash
cd infra/ansible
ansible-galaxy collection install -r requirements.yml
```

Create an API token in Proxmox:
Datacenter → Permissions → API Tokens → add `ansible@pve!automation`,
give it a role with VM.* privileges. Then export the secret:
```bash
export PVE_TOKEN_SECRET=xxxxxxxx-xxxx-...
```

## Run
```bash
ansible-playbook playbooks/provision-vms.yml           # create/update all VMs
ansible-playbook playbooks/provision-vms.yml --check   # dry run
```

## Secrets
The token secret is read from the `PVE_TOKEN_SECRET` env var via
`lookup('env', ...)`. For committed secrets use `ansible-vault` instead.
Never commit real token values.
