import pytest
from admission_guard.validator import AdmissionValidator


@pytest.fixture
def validator():
    return AdmissionValidator()


def make_review(uid: str, namespace: str, spec: dict) -> dict:
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {"uid": uid, "namespace": namespace, "operation": "CREATE", "object": {"spec": spec}},
    }


def test_restricted_pod_allowed(validator):
    spec = {
        "containers": [{
            "name": "app", "image": "repo/app:v1",
            "securityContext": {
                "allowPrivilegeEscalation": False, "runAsNonRoot": True,
                "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]},
            },
        }]
    }
    res = validator.handle_admission_review(make_review("uid-1", "prod", spec))
    assert res["response"]["allowed"] is True
    assert res["response"]["status"]["code"] == 200


def test_privilege_escalation_denied(validator):
    spec = {
        "containers": [{
            "name": "bad-app", "image": "nginx",
            "securityContext": {"allowPrivilegeEscalation": True, "runAsNonRoot": True, "readOnlyRootFilesystem": True},
        }]
    }
    res = validator.handle_admission_review(make_review("uid-2", "default", spec))
    assert res["response"]["allowed"] is False
    assert "allowPrivilegeEscalation: false" in res["response"]["status"]["message"]


def test_root_user_and_mutable_fs_denied(validator):
    spec = {
        "containers": [{
            "name": "root-app", "image": "alpine",
            "securityContext": {"allowPrivilegeEscalation": False, "runAsNonRoot": False, "readOnlyRootFilesystem": False},
        }]
    }
    res = validator.handle_admission_review(make_review("uid-3", "default", spec))
    assert res["response"]["allowed"] is False
    assert "runAsNonRoot: true" in res["response"]["status"]["message"]


def test_host_namespace_denied(validator):
    spec = {
        "hostPID": True,
        "containers": [{
            "name": "spy", "image": "busybox",
            "securityContext": {"allowPrivilegeEscalation": False, "runAsNonRoot": True, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
        }],
    }
    res = validator.handle_admission_review(make_review("uid-4", "default", spec))
    assert res["response"]["allowed"] is False
    assert "hostPID: true" in res["response"]["status"]["message"]


def test_exempt_namespace_bypassed(validator):
    spec = {"hostNetwork": True, "containers": [{"name": "kube-proxy", "image": "k8s/proxy"}]}
    res = validator.handle_admission_review(make_review("uid-5", "kube-system", spec))
    assert res["response"]["allowed"] is True
    assert "Exempt" in res["response"]["status"]["message"]
