"""Schemas de la app de gobernanza."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Origin = Literal["human", "ai", "mixed"]


class FindingOut(BaseModel):
    source: str = ""
    rule_id: str = ""
    severity: str = "low"
    description: str = ""
    file: str = ""
    line: int | None = None
    snippet: str = ""


class ChangeOut(BaseModel):
    id: str
    repo_target_id: str
    repo_name: str = ""
    commit_sha: str
    author_name: str
    author_email: str
    committed_at: datetime
    message: str
    origin: str
    ai_tool: str
    ai_model: str
    prompt_ref: str
    detection: str
    lines_added: int
    lines_removed: int
    files_changed: int
    files: list[str] = []
    findings: list[FindingOut] = []
    review_status: str
    review_count: int
    reviewed_by: str
    reviewed_at: datetime | None
    gate_status: str
    gate_policy_name: str


class ChangePage(BaseModel):
    total: int
    items: list[ChangeOut]


class OriginDeclaration(BaseModel):
    origin: Origin
    ai_tool: str = Field(default="", max_length=100)
    ai_model: str = Field(default="", max_length=150)
    prompt_ref: str = Field(default="", max_length=500)


class ReviewIn(BaseModel):
    decision: Literal["approve", "reject"]
    comment: str = Field(default="", max_length=500)


class GateViolation(BaseModel):
    code: str
    message: str


class GateResult(BaseModel):
    allowed: bool
    status: str
    mode: str
    policy: str
    policy_id: str | None = None
    violations: list[GateViolation] = []
    change_id: str
    commit_sha: str


class GateEvaluateIn(BaseModel):
    repo_target_id: str | None = None
    repo_url: str | None = None
    commit_sha: str = Field(min_length=7, max_length=64)
    message: str = Field(default="", max_length=5000)
    author_name: str = Field(default="", max_length=255)
    author_email: str = Field(default="", max_length=255)
    origin: Origin | None = None
    ai_tool: str = Field(default="", max_length=100)
    ai_model: str = Field(default="", max_length=150)
    prompt_ref: str = Field(default="", max_length=500)
    files: list[str] = Field(default_factory=list, max_length=500)
    lines_added: int = Field(default=0, ge=0)
    lines_removed: int = Field(default=0, ge=0)
    diff: str | None = Field(default=None, max_length=1_000_000)
    findings: list[FindingOut] = Field(default_factory=list, max_length=100)


class GateRunOut(BaseModel):
    id: str
    repo_target_id: str
    repo_name: str = ""
    change_id: str
    commit_sha: str
    status: str
    mode: str
    policy_name: str
    violations: list[GateViolation] = []
    trigger: str
    created_at: datetime


class PolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    repo_target_id: str | None = None
    path_prefixes: str = Field(default="", max_length=1000)
    ai_policy: Literal["allowed", "restricted", "forbidden"] = "allowed"
    required_reviews: int = Field(default=0, ge=0, le=3)
    block_on_severity: Literal["none", "critical", "high", "medium"] = "high"
    mode: Literal["observe", "enforce"] = "observe"
    is_active: bool = True


class PolicyOut(PolicyIn):
    id: str
    repo_name: str = ""
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class LedgerEntryOut(BaseModel):
    seq: int
    ts: str
    event_type: str
    actor: str
    subject: str
    payload: dict
    prev_hash: str
    entry_hash: str
    signature: str


class LedgerPage(BaseModel):
    total: int
    items: list[LedgerEntryOut]


class VerifyOut(BaseModel):
    ok: bool
    entries: int
    head_hash: str
    broken_at_seq: int | None
    reason: str
    anchor_checked: bool = False


class AnchorOut(BaseModel):
    entries: int
    head_hash: str
    generated_at: str
    signature: str
