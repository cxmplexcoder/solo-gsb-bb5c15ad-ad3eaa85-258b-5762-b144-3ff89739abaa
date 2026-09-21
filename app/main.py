"""FastAPI 应用入口。

启动时初始化 SQLite（``MIME_DB_PATH`` 指定路径，默认
``/data/mime.db``），监听 8000 端口（见 Dockerfile / compose）。
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import asynccontextmanager
from typing import Literal, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response

from . import database
from .displaybody import select_display_body
from .errors import MIMEParseError
from .mimeparser import fingerprint, parse_message, raw_sha256
from .related import audit_related_resources
from .security import (
    DEFAULT_FORBIDDEN_MEDIA_TYPES,
    DEFAULT_MAX_ATTACHMENTS,
    DEFAULT_MAX_DECODED_BYTES,
    DEFAULT_MAX_DEPTH,
    SecurityPolicy,
    evaluate_security,
    parse_forbidden_media_types,
)
from .schemas import (
    AttachmentListResponse,
    AttachmentOccurrence,
    AttachmentSummary,
    DisplayBodyResponse,
    DisplayBodyStep,
    MessageCreated,
    MessageListResponse,
    MessageSummary,
    NodeDetail,
    NodeDetailResponse,
    NodeListResponse,
    NodeSummary,
    RelatedOrphan,
    RelatedReference,
    RelatedResourcesResponse,
    RelatedScope,
    SecurityLimits,
    SecurityReportResponse,
    SecurityTotals,
    SecurityViolation,
    TreeNode,
    TreeResponse,
)

DEFAULT_DB_PATH = "/data/mime.db"


def _resolve_db_path() -> str:
    """运行时读取，便于环境变量在启动/测试时覆盖。"""

    return os.environ.get("MIME_DB_PATH", DEFAULT_DB_PATH)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时初始化数据库（幂等）。
    db_path = _resolve_db_path()
    database.init_db(db_path)
    app.state.db_path = db_path
    yield


app = FastAPI(
    title="MIME 邮件归档指纹 API",
    description=(
        "接收原始 RFC 5322 邮件，递归解析 MIME 树，按规范化头字段与"
        "叶子内容生成稳定指纹并入库。相同内容不同换行/头字段大小写"
        "得到同一指纹；损坏输入返回定位到节点的 422 错误且不写入。"
        "非文本叶子的解码字节按 SHA-256 去重进入内容寻址附件库，"
        "支持分页检索与带 Range 的下载。另提供 /messages/{id}/"
        "related-resources 审计 text/html 对 cid: 内嵌资源的引用，"
        "以最近 multipart/related 祖先为作用域匹配 Content-ID。"
        "/messages/{id}/display-body 则按 multipart/alternative、"
        "multipart/related（start 参数）与 multipart/mixed 的递归"
        "规则选出客户端应展示的正文，并返回逐层选择轨迹。"
        "/messages/{id}/security-report 对已归档 MIME 树执行确定性"
        "的附件安全策略评估（双扩展名/控制字符文件名、禁止媒体类型、"
        "嵌套报文与解码字节/附件数/深度阈值），纯只读。"
    ),
    version="1.4.0",
    lifespan=lifespan,
)


def get_conn(request: Request) -> sqlite3.Connection:
    conn = database.connect(request.app.state.db_path)
    try:
        yield conn
    finally:
        conn.close()


@app.exception_handler(MIMEParseError)
async def mime_parse_error_handler(request: Request, exc: MIMEParseError):
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=422, content=exc.to_dict())


# ---------------------------------------------------------------------------
# 节点序列化
# ---------------------------------------------------------------------------


def _node_summary(row: sqlite3.Row) -> NodeSummary:
    return NodeSummary(
        path=row["path"],
        depth=row["depth"],
        position=row["position"],
        content_type=row["content_type"],
        kind=row["kind"],
        cte=row["cte"],
        disposition=row["disposition"],
        children=json.loads(row["children_json"]),
    )


def _message_404(message_id: int) -> HTTPException:
    return HTTPException(status_code=404, detail=f"邮件 {message_id} 不存在")


# ---------------------------------------------------------------------------
# 接口
# ---------------------------------------------------------------------------


@app.get("/health")
def health(request: Request) -> dict:
    return {"status": "ok", "database": request.app.state.db_path}


@app.post("/messages", status_code=201, response_model=MessageCreated)
async def create_message(
    request: Request,
    conn: sqlite3.Connection = Depends(get_conn),
) -> MessageCreated:
    """归档一封原始邮件。

    请求体即邮件原始字节（建议 ``Content-Type: message/rfc822``，
    但服务端只关心字节，不依赖该头）。解析或解码失败时返回 422，
    响应中的 ``node_path`` 标出出错节点。
    """

    data = await request.body()
    if not data:
        raise HTTPException(status_code=400, detail="请求体为空：需要原始 RFC 5322 邮件")

    # 先完整解析+指纹；任何错误都在 save_message 之前抛出，
    # 数据库不会被触碰（“不写入半成品”）。
    tree = parse_message(data)
    fp, canonical = fingerprint(tree)

    message_id, created = database.save_message(
        conn,
        fingerprint=fp,
        raw_hash=raw_sha256(data),
        canonical=canonical,
        size=len(data),
        root=tree,
    )
    row = database.get_message(conn, message_id)
    node_count = len(database.list_nodes(conn, message_id))
    assert row is not None
    return MessageCreated(
        id=message_id,
        fingerprint=row["fingerprint"],
        raw_sha256=row["raw_sha256"],
        content_type=row["content_type"],
        size_bytes=row["size_bytes"],
        created=created,
        node_count=node_count,
    )


@app.get("/messages", response_model=MessageListResponse)
def list_messages(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    conn: sqlite3.Connection = Depends(get_conn),
) -> MessageListResponse:
    rows = database.list_messages(conn, limit=limit, offset=offset)
    return MessageListResponse(
        items=[
            MessageSummary(
                id=r["id"],
                fingerprint=r["fingerprint"],
                raw_sha256=r["raw_sha256"],
                content_type=r["content_type"],
                size_bytes=r["size_bytes"],
                created_at=r["created_at"],
            )
            for r in rows
        ],
        total=database.count_messages(conn),
        limit=limit,
        offset=offset,
    )


@app.get("/messages/{message_id}", response_model=MessageSummary)
def get_message(
    message_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
) -> MessageSummary:
    row = database.get_message(conn, message_id)
    if row is None:
        raise _message_404(message_id)
    return MessageSummary(
        id=row["id"],
        fingerprint=row["fingerprint"],
        raw_sha256=row["raw_sha256"],
        content_type=row["content_type"],
        size_bytes=row["size_bytes"],
        created_at=row["created_at"],
    )


@app.get("/messages/{message_id}/tree", response_model=TreeResponse)
def get_tree(
    message_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
) -> TreeResponse:
    """返回嵌套 MIME 树（children 内嵌完整子节点）。"""

    msg = database.get_message(conn, message_id)
    if msg is None:
        raise _message_404(message_id)
    rows = database.list_nodes(conn, message_id)
    root_row = next(r for r in rows if r["path"] == "")
    root = _build_nested(root_row, rows)
    return TreeResponse(id=message_id, fingerprint=msg["fingerprint"], tree=root)


def _build_nested(row: sqlite3.Row, rows: list[sqlite3.Row]) -> TreeNode:
    by_path = {r["path"]: r for r in rows}
    children_paths = json.loads(row["children_json"])
    return TreeNode(
        path=row["path"],
        depth=row["depth"],
        position=row["position"],
        content_type=row["content_type"],
        kind=row["kind"],
        cte=row["cte"],
        disposition=row["disposition"],
        children=[
            _build_nested(by_path[p], rows) for p in children_paths
        ],
    )


@app.get("/messages/{message_id}/nodes", response_model=NodeListResponse)
def list_nodes(
    message_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
) -> NodeListResponse:
    """扁平返回全部节点（children 为子节点路径）。"""

    msg = database.get_message(conn, message_id)
    if msg is None:
        raise _message_404(message_id)
    rows = database.list_nodes(conn, message_id)
    return NodeListResponse(
        id=message_id,
        fingerprint=msg["fingerprint"],
        nodes=[_node_summary(r) for r in rows],
    )


@app.get(
    "/messages/{message_id}/nodes/{node_path:path}",
    response_model=NodeDetailResponse,
)
def get_node(
    message_id: int,
    node_path: str,
    conn: sqlite3.Connection = Depends(get_conn),
) -> NodeDetailResponse:
    """查询单个节点详情（含头字段与叶子内容）。

    根节点路径为空，使用 ``/messages/{id}/nodes/``（末尾斜杠）。
    """

    msg = database.get_message(conn, message_id)
    if msg is None:
        raise _message_404(message_id)
    row = database.get_node(conn, message_id, node_path)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"节点 {node_path!r} 不存在",
        )
    detail = NodeDetail(
        **_node_summary(row).model_dump(),
        headers=json.loads(row["headers_json"]),
        text=row["text_content"],
        blob_sha256=row["blob_sha256"],
        blob_length=row["blob_length"],
    )
    return NodeDetailResponse(
        id=message_id, fingerprint=msg["fingerprint"], node=detail
    )


# ---------------------------------------------------------------------------
# 展示正文选择
# ---------------------------------------------------------------------------


@app.get(
    "/messages/{message_id}/display-body",
    response_model=DisplayBodyResponse,
)
def get_display_body(
    message_id: int,
    prefer: Literal["html", "plain"] = Query(
        "html",
        description="客户端优先展示的正文格式（multipart/alternative 中优先）",
    ),
    conn: sqlite3.Connection = Depends(get_conn),
) -> DisplayBodyResponse:
    """从已归档 MIME 树选出客户端应展示的正文（纯只读，不改写记录）。

    递归规则：

    * ``multipart/alternative``：在可展示分支中优先选择实际正文匹配
      ``prefer``（``text/html`` / ``text/plain``）的分支；否则取
      **最后一个可展示分支**（RFC 2046 末位最忠实）；
    * ``multipart/related``：按容器 ``start`` 参数（RFC 2387）匹配
      直接子件的 Content-ID；未配置时取**首个子件**；
    * ``multipart/mixed`` 等其他容器：取**首个可展示子件**。

    ``Content-Disposition: attachment`` 节点与
    ``message/rfc822`` / ``message/global`` 封装报文内部正文不作为
    候选；非文本叶子同样不可展示。无可展示正文返回 **404**；
    ``start`` 重复命中（或未命中）返回 **422**，错误体
    ``node_path`` 定位到对应的 multipart/related 节点。
    """

    msg = database.get_message(conn, message_id)
    if msg is None:
        raise _message_404(message_id)
    rows = database.list_nodes(conn, message_id)

    # start 配置错误（重复命中/未命中）抛 MIMEParseError，由全局
    # 异常处理器转成带 node_path 的 422。
    selection = select_display_body(rows, prefer)
    if selection.leaf is None:
        raise HTTPException(
            status_code=404,
            detail=f"邮件 {message_id} 没有可展示的正文（attachment /"
            " 封装报文 / 非文本叶子均不作为候选）",
        )
    leaf = selection.leaf
    return DisplayBodyResponse(
        id=message_id,
        fingerprint=msg["fingerprint"],
        prefer=prefer,
        node_path=leaf["path"],
        content_type=leaf["content_type"],
        text=leaf["text_content"] if leaf["text_content"] is not None else "",
        trail=[
            DisplayBodyStep(
                node_path=step.node_path,
                content_type=step.content_type,
                rule=step.rule,
                considered=step.considered,
                candidates=step.candidates,
                chosen=step.chosen,
                detail=step.detail,
            )
            for step in selection.steps
        ],
    )


# ---------------------------------------------------------------------------
# cid: 内嵌资源引用审计
# ---------------------------------------------------------------------------


@app.get(
    "/messages/{message_id}/related-resources",
    response_model=RelatedResourcesResponse,
)
def get_related_resources(
    message_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
) -> RelatedResourcesResponse:
    """审计归档邮件 HTML 对 ``cid:`` 内嵌资源的引用。

    从每个 **text/html 叶子** 的 ``src`` / ``href`` / ``poster`` /
    ``srcset`` 属性按文档序提取 ``cid:`` 引用，RFC 2392 百分号解码后，
    以该叶子 **最近的 ``multipart/related`` 祖先**为唯一作用域匹配
    ``Content-ID``：

    * 唯一命中 → ``resolved``（给 ``target_node_path``）；
    * 同作用域重复 Content-ID → ``ambiguous``（给全部 ``candidates``）；
    * 无命中或 HTML 不在任何 related 作用域 → ``missing``；
    * 不跨相邻兄弟作用域、也不向内层嵌套作用域串联。

    响应的 ``scopes`` 按文档序列出每个 multipart/related 作用域中
    未被引用的 Content-ID 节点（orphan）。邮件不存在返回 404。
    """

    msg = database.get_message(conn, message_id)
    if msg is None:
        raise _message_404(message_id)
    rows = database.list_nodes(conn, message_id)
    refs, scopes = audit_related_resources(rows)
    return RelatedResourcesResponse(
        id=message_id,
        fingerprint=msg["fingerprint"],
        references=[
            RelatedReference(
                source_node_path=r.source_node_path,
                attribute=r.attribute,
                cid=r.cid,
                scope_node_path=r.scope_node_path,
                status=r.status,
                target_node_path=r.target_node_path,
                candidates=r.candidates,
            )
            for r in refs
        ],
        scopes=[
            RelatedScope(
                node_path=s["node_path"],
                orphans=[RelatedOrphan(**o) for o in s["orphans"]],
            )
            for s in scopes
        ],
    )


# ---------------------------------------------------------------------------
# 附件安全策略评估
# ---------------------------------------------------------------------------


@app.get(
    "/messages/{message_id}/security-report",
    response_model=SecurityReportResponse,
)
def get_security_report(
    message_id: int,
    max_decoded_bytes: int = Query(
        DEFAULT_MAX_DECODED_BYTES,
        ge=0,
        description="解码字节总量上限（严格大于即违规）",
    ),
    max_attachments: int = Query(
        DEFAULT_MAX_ATTACHMENTS,
        ge=0,
        description="附件节点数量上限（严格大于即违规）",
    ),
    max_depth: int = Query(
        DEFAULT_MAX_DEPTH,
        ge=0,
        description="MIME 树最大深度上限（严格大于即违规）",
    ),
    forbidden_media_types: Optional[str] = Query(
        None,
        max_length=2000,
        description="逗号分隔的禁止媒体类型清单（type/subtype），"
        "提供时整体替换默认清单",
    ),
    conn: sqlite3.Connection = Depends(get_conn),
) -> SecurityReportResponse:
    """对已归档 MIME 树执行确定性的附件安全策略评估（纯只读）。

    从根节点按物化路径递归累计解码字节、附件数量与 MIME 深度，并逐
    节点检查：附件文件名的双扩展名（``DOUBLE_EXTENSION``）与控制
    字符（``CONTROL_CHAR_IN_FILENAME``）、禁止媒体类型
    （``FORBIDDEN_MEDIA_TYPE``）、嵌套 ``message/rfc822`` /
    ``message/global`` 封装报文（``NESTED_MESSAGE``）；总量超过阈值
    时追加 ``DECODED_BYTES_EXCEEDED`` / ``TOO_MANY_ATTACHMENTS`` /
    ``MAX_DEPTH_EXCEEDED``。任一命中即 ``allow=false``。

    阈值与禁止清单均可由查询参数覆盖默认值；参数非法（负数、非整数、
    非法媒体类型）返回 **422**；邮件不存在返回 **404**。评估只读取
    归档时保存的节点，不修改任何记录，同一归档重复请求结果一致。
    """

    # 先校验策略参数（请求形状错误优先于资源缺失）。
    if forbidden_media_types is None:
        forbidden = DEFAULT_FORBIDDEN_MEDIA_TYPES
    else:
        try:
            forbidden = parse_forbidden_media_types(forbidden_media_types)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    msg = database.get_message(conn, message_id)
    if msg is None:
        raise _message_404(message_id)
    rows = database.list_nodes(conn, message_id)

    policy = SecurityPolicy(
        max_decoded_bytes=max_decoded_bytes,
        max_attachments=max_attachments,
        max_depth=max_depth,
        forbidden_media_types=forbidden,
    )
    report = evaluate_security(rows, policy)
    return SecurityReportResponse(
        id=message_id,
        fingerprint=msg["fingerprint"],
        allow=not report.violations,
        limits=SecurityLimits(
            max_decoded_bytes=policy.max_decoded_bytes,
            max_attachments=policy.max_attachments,
            max_depth=policy.max_depth,
            forbidden_media_types=list(policy.forbidden_media_types),
        ),
        totals=SecurityTotals(
            decoded_bytes=report.totals.decoded_bytes,
            attachments=report.totals.attachments,
            max_depth=report.totals.max_depth,
        ),
        violations=[
            SecurityViolation(
                code=v.code, node_path=v.node_path, detail=v.detail
            )
            for v in report.violations
        ],
    )


# ---------------------------------------------------------------------------
# 附件库
# ---------------------------------------------------------------------------


@app.get("/attachments", response_model=AttachmentListResponse)
def list_attachments(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    sha256: Optional[str] = Query(
        None,
        pattern=r"^[0-9a-fA-F]{1,64}$",
        description="按哈希前缀过滤（传完整 64 位即精确查找）",
    ),
    filename: Optional[str] = Query(
        None, max_length=200, description="按解码文件名子串过滤"
    ),
    media_type: Optional[str] = Query(
        None, max_length=100, description="按出现位置的媒体类型精确过滤"
    ),
    conn: sqlite3.Connection = Depends(get_conn),
) -> AttachmentListResponse:
    """分页列出附件实体，每项含引用次数与全部出现位置。"""

    rows = database.list_attachments(
        conn,
        limit=limit,
        offset=offset,
        sha256=sha256,
        filename=filename,
        media_type=media_type,
    )
    items = [
        AttachmentSummary(
            sha256=r["sha256"],
            size_bytes=r["size_bytes"],
            media_type=r["media_type"],
            reference_count=r["reference_count"],
            created_at=r["created_at"],
            occurrences=[
                AttachmentOccurrence(**dict(ref))
                for ref in database.list_attachment_refs(conn, r["sha256"])
            ],
        )
        for r in rows
    ]
    return AttachmentListResponse(
        items=items,
        total=database.count_attachments(
            conn, sha256=sha256, filename=filename, media_type=media_type
        ),
        limit=limit,
        offset=offset,
    )


def _parse_single_range(header: str, size: int) -> Optional[tuple[int, int]]:
    """解析单段 ``bytes`` Range，返回闭区间 ``(start, end)``。

    多段、语法非法、越界等一律返回 ``None``（调用方据此回 416）。
    合法的开口/后缀/超界末端按 RFC 7233 收敛到实际范围。
    """

    unit, sep, spec = header.partition("=")
    if not sep or unit.strip().lower() != "bytes":
        return None
    ranges = [r.strip() for r in spec.split(",")]
    if len(ranges) != 1 or not ranges[0]:
        return None
    start_s, dash, end_s = ranges[0].partition("-")
    if not dash:
        return None
    if not start_s:
        # 后缀范围：最后 N 字节
        if not end_s.isdigit():
            return None
        suffix = int(end_s)
        if suffix <= 0:
            return None
        start = max(size - suffix, 0)
        end = size - 1
    else:
        if not start_s.isdigit() or (end_s and not end_s.isdigit()):
            return None
        start = int(start_s)
        end = int(end_s) if end_s else size - 1
        if start > end:
            return None
        end = min(end, size - 1)
    if start >= size:  # 越界（含空附件）
        return None
    return start, end


@app.get("/attachments/{sha256}/content")
def get_attachment_content(
    sha256: str,
    request: Request,
    conn: sqlite3.Connection = Depends(get_conn),
) -> Response:
    """下载附件的原始解码字节。

    支持单段 ``bytes`` Range：合法范围返回 206 与 ``Content-Range``；
    越界、多段或非法范围返回 416（带 ``Content-Range: bytes */N``）。
    """

    row = database.get_attachment(conn, sha256.lower())
    if row is None:
        raise HTTPException(status_code=404, detail=f"附件 {sha256} 不存在")
    content: bytes = row["content"]
    size: int = row["size_bytes"]
    media_type: str = row["media_type"]

    range_header = request.headers.get("range")
    if range_header is None:
        return Response(
            content=content,
            media_type=media_type,
            headers={"Accept-Ranges": "bytes"},
        )

    parsed = _parse_single_range(range_header, size)
    if parsed is None:
        raise HTTPException(
            status_code=416,
            detail=(
                f"Range 不可满足：{range_header!r}"
                f"（资源大小 {size} 字节，仅支持单段 bytes 范围）"
            ),
            headers={"Content-Range": f"bytes */{size}"},
        )
    start, end = parsed
    return Response(
        content=content[start:end + 1],
        status_code=206,
        media_type=media_type,
        headers={
            "Content-Range": f"bytes {start}-{end}/{size}",
            "Accept-Ranges": "bytes",
        },
    )
