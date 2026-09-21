"""API 响应模型。"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class MessageSummary(BaseModel):
    id: int
    fingerprint: str
    raw_sha256: str
    content_type: str
    size_bytes: int
    created_at: str


class MessageListResponse(BaseModel):
    items: list[MessageSummary]
    total: int
    limit: int
    offset: int


class MessageCreated(BaseModel):
    id: int
    fingerprint: str
    raw_sha256: str
    content_type: str
    size_bytes: int
    created: bool  # True=新入库；False=同指纹邮件已存在（幂等）
    node_count: int


class NodeSummary(BaseModel):
    path: str
    depth: int
    position: int
    content_type: str
    kind: str
    cte: str
    disposition: Optional[str] = None
    children: list[str]


class TreeNode(BaseModel):
    """嵌套 MIME 树节点，children 为完整子树。"""

    path: str
    depth: int
    position: int
    content_type: str
    kind: str
    cte: str
    disposition: Optional[str] = None
    children: list["TreeNode"] = []


TreeNode.model_rebuild()


class TreeResponse(BaseModel):
    id: int
    fingerprint: str
    tree: TreeNode


class NodeListResponse(BaseModel):
    id: int
    fingerprint: str
    nodes: list[NodeSummary]


class NodeDetail(NodeSummary):
    headers: list[list[str]]
    text: Optional[str] = None
    blob_sha256: Optional[str] = None
    blob_length: Optional[int] = None


class NodeDetailResponse(BaseModel):
    id: int
    fingerprint: str
    node: NodeDetail


class AttachmentOccurrence(BaseModel):
    """附件的一次出现：哪封邮件的哪个节点、以什么文件名/处置方式。"""

    message_id: int
    node_path: str
    filename: Optional[str] = None
    disposition: Optional[str] = None
    media_type: str


class AttachmentSummary(BaseModel):
    sha256: str
    size_bytes: int
    media_type: str  # 首次归档时的媒体类型
    reference_count: int
    created_at: str
    occurrences: list[AttachmentOccurrence]


class AttachmentListResponse(BaseModel):
    items: list[AttachmentSummary]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# cid: 内嵌资源引用审计（GET /messages/{id}/related-resources）
# ---------------------------------------------------------------------------


class RelatedReference(BaseModel):
    """一条来自 text/html 叶子的 ``cid:`` 引用及其解析结果。"""

    source_node_path: str
    attribute: str  # src / href / poster / srcset
    cid: str  # RFC 2392 百分号解码后的目标 Content-ID
    # 最近的 multipart/related 祖先；HTML 不在任何 related 作用域时为 None
    scope_node_path: Optional[str] = None
    status: str  # resolved | missing | ambiguous
    target_node_path: Optional[str] = None  # status == resolved
    candidates: list[str] = []  # status == ambiguous 时的全部候选节点


class RelatedOrphan(BaseModel):
    """作用域内声明了 Content-ID 却未被该作用域 HTML 引用的节点。"""

    node_path: str
    content_type: str
    content_ids: list[str]


class RelatedScope(BaseModel):
    """一个 multipart/related 容器的审计侧影。"""

    node_path: str
    orphans: list[RelatedOrphan]


class RelatedResourcesResponse(BaseModel):
    id: int
    fingerprint: str
    references: list[RelatedReference]
    scopes: list[RelatedScope]


# ---------------------------------------------------------------------------
# 展示正文选择（GET /messages/{id}/display-body）
# ---------------------------------------------------------------------------


class DisplayBodyStep(BaseModel):
    """容器节点上的一次逐层选择（选择轨迹中的一项）。"""

    node_path: str
    content_type: str
    rule: str  # alternative-prefer | alternative-fallback-last
    # related-start | related-first | first-displayable
    considered: list[str]  # 该层实际评估过的直接子件路径（文档序）
    candidates: list[str]  # 规则下合格的候选子件路径（文档序）
    chosen: Optional[str]  # 实际进入的子件路径
    detail: dict = {}  # {"prefer": "html"} 或 {"start": "<cid>"}


class DisplayBodyResponse(BaseModel):
    id: int
    fingerprint: str
    prefer: str  # html | plain
    node_path: str
    content_type: str
    text: str
    trail: list[DisplayBodyStep]


# ---------------------------------------------------------------------------
# 附件安全策略评估（GET /messages/{id}/security-report）
# ---------------------------------------------------------------------------


class SecurityViolation(BaseModel):
    """一条安全规则命中。"""

    code: str
    node_path: str
    detail: dict


class SecurityTotals(BaseModel):
    """按节点路径递归累计的规模量。"""

    decoded_bytes: int  # 全部非文本叶子的解码字节合计
    attachment_count: int  # 非文本叶子（附件）个数
    max_depth: int  # MIME 树最大深度（根为 0）


class SecurityThresholds(BaseModel):
    """本次评估实际生效的阈值（默认值或查询参数覆盖后的值）。"""

    max_decoded_bytes: int
    max_attachment_count: int
    max_mime_depth: int


class SecurityReportResponse(BaseModel):
    id: int
    fingerprint: str
    allow: bool  # 无任何 violation 时为 true
    totals: SecurityTotals
    thresholds: SecurityThresholds
    violations: list[SecurityViolation]


class ErrorBody(BaseModel):
    code: str
    message: str
    node_path: str
    detail: dict


class ErrorResponse(BaseModel):
    error: ErrorBody
