from typing import List, Dict, Any, Set, Optional
from .models import (
    PodSpec,
    ContainerSpec,
    AdmissionReviewRequest,
    AdmissionReviewResponse,
)


class AdmissionValidator:
    """Validating Admission Controller for Kubernetes Pod Security Standards (Restricted)."""

    def __init__(self, exempt_namespaces: Optional[Set[str]] = None):
        self.exempt_namespaces: Set[str] = exempt_namespaces or {
            "kube-system",
            "kube-public",
            "kube-node-lease",
        }

    def evaluate_container_security(self, container: ContainerSpec) -> List[str]:
        violations: List[str] = []
        sec = container.security_context

        if not sec:
            violations.append(f"container '{container.name}' is missing securityContext")
            return violations

        if sec.privileged:
            violations.append(f"container '{container.name}' must not run as privileged")

        if sec.allow_privilege_escalation is not False:
            violations.append(
                f"container '{container.name}' must explicitly set allowPrivilegeEscalation: false"
            )

        if sec.run_as_non_root is not True:
            violations.append(
                f"container '{container.name}' must explicitly set runAsNonRoot: true"
            )

        if sec.read_only_root_filesystem is not True:
            violations.append(
                f"container '{container.name}' must set readOnlyRootFilesystem: true"
            )

        caps = sec.capabilities
        if not caps or "ALL" not in [c.upper() for c in caps.drop]:
            violations.append(
                f"container '{container.name}' must drop 'ALL' capabilities"
            )

        return violations

    def evaluate_pod_security(self, spec: PodSpec) -> List[str]:
        violations: List[str] = []

        if spec.host_network:
            violations.append("pod must not share host network namespace (hostNetwork: true)")
        if spec.host_pid:
            violations.append("pod must not share host PID namespace (hostPID: true)")
        if spec.host_ipc:
            violations.append("pod must not share host IPC namespace (hostIPC: true)")

        for c in spec.containers:
            violations.extend(self.evaluate_container_security(c))
        for c in spec.init_containers:
            violations.extend(self.evaluate_container_security(c))

        return violations

    def handle_admission_review(self, review_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Process v1.AdmissionReview request dict and return response dict."""
        req_raw = review_dict.get("request", {})
        req = AdmissionReviewRequest(
            uid=req_raw.get("uid", ""),
            namespace=req_raw.get("namespace", "default"),
            operation=req_raw.get("operation", "CREATE"),
            object=req_raw.get("object", {}),
        )

        # Namespace exemptions
        if req.namespace in self.exempt_namespaces:
            return self._build_response(req.uid, allowed=True, message="Exempt system namespace")

        spec_raw = req.object.get("spec", {})
        try:
            pod_spec = PodSpec.model_validate(spec_raw)
        except Exception as e:
            return self._build_response(
                req.uid, allowed=False, status_code=400, message=f"Invalid PodSpec schema: {str(e)}"
            )

        violations = self.evaluate_pod_security(pod_spec)
        if violations:
            msg = f"Pod security validation failed: {'; '.join(violations)}"
            return self._build_response(req.uid, allowed=False, status_code=403, message=msg)

        return self._build_response(req.uid, allowed=True, message="Pod passed Restricted security standards")

    def _build_response(
        self, uid: str, allowed: bool, status_code: int = 200, message: Optional[str] = None
    ) -> Dict[str, Any]:
        resp = AdmissionReviewResponse(
            uid=uid,
            allowed=allowed,
            status_code=status_code,
            message=message,
        )
        return {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": resp.uid,
                "allowed": resp.allowed,
                "status": {
                    "code": resp.status_code,
                    "message": resp.message or "",
                },
            },
        }
