from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class Capabilities(BaseModel):
    drop: List[str] = Field(default_factory=list)
    add: List[str] = Field(default_factory=list)


class SecurityContext(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    allow_privilege_escalation: Optional[bool] = Field(default=None, alias="allowPrivilegeEscalation")
    run_as_non_root: Optional[bool] = Field(default=None, alias="runAsNonRoot")
    read_only_root_filesystem: Optional[bool] = Field(default=None, alias="readOnlyRootFilesystem")
    privileged: Optional[bool] = Field(default=False)
    capabilities: Optional[Capabilities] = None


class ContainerSpec(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    image: str
    security_context: Optional[SecurityContext] = Field(default=None, alias="securityContext")


class PodSpec(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    containers: List[ContainerSpec] = Field(default_factory=list)
    init_containers: List[ContainerSpec] = Field(default_factory=list, alias="initContainers")
    host_network: bool = Field(default=False, alias="hostNetwork")
    host_pid: bool = Field(default=False, alias="hostPID")
    host_ipc: bool = Field(default=False, alias="hostIPC")


class AdmissionReviewRequest(BaseModel):
    uid: str
    namespace: str
    operation: str
    object: Dict[str, Any]


class AdmissionReviewResponse(BaseModel):
    uid: str
    allowed: bool
    status_code: int = 200
    message: Optional[str] = None
