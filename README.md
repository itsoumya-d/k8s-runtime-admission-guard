# Kubernetes Runtime Admission Guard

A lightweight, production-grade Kubernetes Validating Admission Controller that inspects Pod specifications against Pod Security Standards (Restricted Profile).

## Key Security Policies Enforced
- **Privilege Escalation Prevention**: Rejects pods running with `allowPrivilegeEscalation: true`.
- **Root User Execution Denial**: Blocks containers running as `root` (`runAsNonRoot: true` required).
- **Read-Only Root Filesystem**: Enforces `readOnlyRootFilesystem: true` to prevent runtime container tampering.
- **Linux Capability Drops**: Demands `ALL` capabilities dropped, allowing only designated unprivileged overrides.
- **Host Namespace Isolation**: Prevents `hostPID`, `hostIPC`, and `hostNetwork` access.

## Verification & Testing
```bash
python3 -m pip install -e ".[test]"
pytest -v
```
