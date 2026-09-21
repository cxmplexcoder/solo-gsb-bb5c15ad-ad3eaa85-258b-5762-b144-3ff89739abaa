"""附件安全策略评估（``GET /messages/{id}/security-report``）。

在**已归档 MIME 树**上执行确定性的只读安全评估：输入为
:func:`database.list_nodes` 返回的节点行（含 ``children_json`` /
``headers_json``），不回写任何记录，因此同一归档重复评估结果完全
一致，对历史归档数据同样适用。

从根节点按物化路径**递归**累计三项总量（``totals``）：

* ``decoded_bytes`` —— 全部叶子的解码字节数：``blob`` 叶子取归档时
  留存的解码长度（``blob_length``），``text`` 叶子取规范化文本的
  UTF-8 编码长度；
* ``attachments`` —— 附件节点数：``Content-Disposition: attachment``
  **或**声明了文件名（Content-Disposition ``filename`` /
  Content-Type ``name``，均已完成 RFC 2231 解码）的节点；
* ``max_depth`` —— 树的最大 MIME 深度（根为 0）。

逐节点策略检查（每次命中产生一条 violation，含 ``code`` /
``node_path`` / ``detail``）：

* ``CONTROL_CHAR_IN_FILENAME`` —— 附件文件名含 Unicode 类别
  Cc（控制字符）或 Cf（格式字符，如 U+202E 反向覆盖）的字符；
* ``DOUBLE_EXTENSION`` —— 文件名以两个连续 ASCII 扩展名结尾
  （``invoice.pdf.exe``、``archive.tar.gz`` 均命中）；
* ``FORBIDDEN_MEDIA_TYPE`` —— 附件节点的媒体类型命中禁止清单；
* ``NESTED_MESSAGE`` —— 深度 ≥ 1 的 ``message/rfc822`` /
  ``message/global`` 封装报文（根节点本身是被归档的邮件，不计）。

总量阈值（均可由查询参数覆盖默认值，**严格大于**即违规）：

* ``DECODED_BYTES_EXCEEDED`` —— 解码字节总量超限（定位根节点）；
* ``TOO_MANY_ATTACHMENTS`` —— 附件数量超限（定位根节点）；
* ``MAX_DEPTH_EXCEEDED`` —— MIME 深度超限（定位最深节点）。

任一 violation 命中即 ``allow=false``，否则 ``allow=true``。
violation 顺序确定：先按文档序逐节点输出（节点内按上述检查顺序），
再按字节数、附件数、深度的固定顺序输出阈值违规。
"""

from __future__ import annotations

import json
import re
import sqlite3
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

from .mimeparser import parse_content_type, parse_disposition
from .related import json_loads_headers
from .related import json_loads_headers

# ---------------------------------------------------------------------------
# 默认策略
# ---------------------------------------------------------------------------

DEFAULT_MAX_DECODED_BYTES = 10_000_000
DEFAULT_MAX_ATTACHMENTS = 20
DEFAULT_MAX_DEPTH = 10

# 默认禁止的媒体类型（常见可执行内容，均小写）
DEFAULT_FORBIDDEN_MEDIA_TYPES: tuple[str, ...] = (
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-dosexec",
    "application/x-executable",
    "application/vnd.microsoft.portable-executable",
    "application/x-bat",
    "application/x-sh",
)

# violation code（稳定机器可读，与解析错误码风格一致）
DOUBLE_EXTENSION = "DOUBLE_EXTENSION"
CONTROL_CHAR_IN_FILENAME = "CONTROL_CHAR_IN_FILENAME"
FORBIDDEN_MEDIA_TYPE = "FORBIDDEN_MEDIA_TYPE"
NESTED_MESSAGE = "NESTED_MESSAGE"
DECODED_BYTES_EXCEEDED = "DECODED_BYTES_EXCEEDED"
TOO_MANY_ATTACHMENTS = "TOO_MANY_ATTACHMENTS"
MAX_DEPTH_EXCEEDED = "MAX_DEPTH_EXCEEDED"

_ENCAPSULATED_MESSAGE_TYPES = ("message/rfc822", "message/global")

# 双扩展名：文件名末尾两个连续的 ASCII 扩展名（各 1..10 位字母数字）
_DOUBLE_EXTENSION_RE = re.compile(
    r"\.([A-Za-z0-9]{1,10})\.([A-Za-z0-9]{1,10})$"
)

# 媒体类型 token（RFC 2045 token，与解析器 _TOKEN_STR 同一字母表）
_MEDIA_TYPE_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+\-.^_`{|}~]+/[A-Za-z0-9!#$%&'*+\-.^_`{|}~]+$"
)

# 文件名中禁止的 Unicode 类别：Cc（控制字符）、Cf（格式字符）
_CONTROL_CATEGORIES = ("Cc", "Cf")


# ---------------------------------------------------------------------------
# 策略与结果数据结构
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecurityPolicy:
    """一次评估生效的策略（默认值可经查询参数覆盖）。"""

    max_decoded_bytes: int = DEFAULT_MAX_DECODED_BYTES
    max_attachments: int = DEFAULT_MAX_ATTACHMENTS
    max_depth: int = DEFAULT_MAX_DEPTH
    forbidden_media_types: tuple[str, ...] = DEFAULT_FORBIDDEN_MEDIA_TYPES


@dataclass(frozen=True)
class SecurityViolation:
    """一条策略命中。"""

    code: str
    node_path: str
    detail: dict


@dataclass
class SecurityTotals:
    """整棵 MIME 树递归累计的总量。"""

    decoded_bytes: int = 0
    attachments: int = 0
    max_depth: int = 0


@dataclass
class SecurityReport:
    totals: SecurityTotals
    violations: list[SecurityViolation] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 查询参数解析
# ---------------------------------------------------------------------------


def parse_forbidden_media_types(raw: str) -> tuple[str, ...]:
    """解析逗号分隔的禁止媒体类型清单（查询参数覆盖默认清单用）。

    每项必须是 ``type/subtype`` 形式的合法 token 对（大小写不敏感，
    统一小写、去重并保持顺序）；空项、空清单或非法项抛
    :class:`ValueError`（由 API 层转为 422）。
    """

    items: list[str] = []
    for piece in raw.split(","):
        item = piece.strip().lower()
        if not item or not _MEDIA_TYPE_RE.fullmatch(item):
            raise ValueError(
                f"非法媒体类型 {piece.strip()!r}：应为 type/subtype"
            )
        items.append(item)
    if not items:
        raise ValueError("禁止媒体类型清单不能为空")
    return tuple(dict.fromkeys(items))


# ---------------------------------------------------------------------------
# 节点信息提取
# ---------------------------------------------------------------------------


def _node_filename(row: sqlite3.Row) -> Optional[str]:
    """节点的解码文件名：Content-Disposition ``filename`` 优先，回退
    Content-Type ``name``。

    归档只留存解码后的头值字符串（headers_json），这里用归档器自己的
    严格解析器重新解析取参数（含 RFC 2231 续片/百分号解码）——纯读、
    不碰原始记录，与归档时的解析结果等价（同 displaybody 对 ``start``
    参数的处理）。
    """

    filename: Optional[str] = None
    type_name: Optional[str] = None
    for name, value in json_loads_headers(row["headers_json"]):
        lname = name.lower()
        if lname == "content-disposition":
            _lead, params = parse_disposition(
                value.encode("utf-8"), row["path"]
            )
            if "filename" in params:
                filename = params["filename"]
        elif lname == "content-type":
            ct = parse_content_type(value.encode("utf-8"), row["path"])
            if "name" in ct.params:
                type_name = ct.params["name"]
    return filename if filename is not None else type_name


def _is_attachment(row: sqlite3.Row, filename: Optional[str]) -> bool:
    """附件节点：disposition 为 attachment，或声明了文件名。"""

    return (
        (row["disposition"] or "").lower() == "attachment"
        or filename is not None
    )


def _control_characters(filename: str) -> list[dict]:
    """文件名中的 Cc/Cf 字符（位置 + 码位 + 类别），按出现顺序。"""

    return [
        {
            "position": i,
            "codepoint": f"U+{ord(ch):04X}",
            "category": unicodedata.category(ch),
        }
        for i, ch in enumerate(filename)
        if unicodedata.category(ch) in _CONTROL_CATEGORIES
    ]


# ---------------------------------------------------------------------------
# 评估入口
# ---------------------------------------------------------------------------


def evaluate_security(
    rows: list[sqlite3.Row], policy: SecurityPolicy
) -> SecurityReport:
    """在一封已归档邮件的节点行上执行安全策略评估。

    ``rows`` 为 :func:`database.list_nodes` 的结果。纯函数：同一
    ``rows`` + ``policy`` 必得同一报告，不触碰数据库。
    """

    by_path = {r["path"]: r for r in rows}
    totals = SecurityTotals()
    violations: list[SecurityViolation] = []
    forbidden = set(policy.forbidden_media_types)

    def visit(row: sqlite3.Row) -> None:
        path = row["path"]
        depth = int(row["depth"])
        totals.max_depth = max(totals.max_depth, depth)

        # 解码字节：blob 取留存的解码长度；text 取规范化文本的 UTF-8 长度
        kind = row["kind"]
        if kind == "blob":
            totals.decoded_bytes += int(row["blob_length"] or 0)
        elif kind == "text":
            totals.decoded_bytes += len(
                (row["text_content"] or "").encode("utf-8")
            )

        filename = _node_filename(row)
        if _is_attachment(row, filename):
            totals.attachments += 1
            if filename is not None:
                bad_chars = _control_characters(filename)
                if bad_chars:
                    violations.append(
                        SecurityViolation(
                            CONTROL_CHAR_IN_FILENAME,
                            path,
                            {
                                "filename": filename,
                                "control_characters": bad_chars,
                            },
                        )
                    )
                match = _DOUBLE_EXTENSION_RE.search(filename)
                if match:
                    violations.append(
                        SecurityViolation(
                            DOUBLE_EXTENSION,
                            path,
                            {
                                "filename": filename,
                                "extensions": [
                                    match.group(1).lower(),
                                    match.group(2).lower(),
                                ],
                            },
                        )
                    )
            media_type = row["content_type"].lower()
            if media_type in forbidden:
                violations.append(
                    SecurityViolation(
                        FORBIDDEN_MEDIA_TYPE,
                        path,
                        {"media_type": media_type},
                    )
                )

        # 嵌套封装报文：根节点（depth 0）是被归档的邮件本身，不计。
        if depth >= 1 and (
            kind == "message"
            or row["content_type"].lower() in _ENCAPSULATED_MESSAGE_TYPES
        ):
            violations.append(
                SecurityViolation(
                    NESTED_MESSAGE,
                    path,
                    {
                        "content_type": row["content_type"].lower(),
                        "depth": depth,
                    },
                )
            )

        for child_path in json.loads(row["children_json"]):
            visit(by_path[child_path])

    visit(by_path[""])

    # 总量阈值：严格大于即违规（节点级违规之后按固定顺序追加）。
    if totals.decoded_bytes > policy.max_decoded_bytes:
        violations.append(
            SecurityViolation(
                DECODED_BYTES_EXCEEDED,
                "",
                {
                    "decoded_bytes": totals.decoded_bytes,
                    "max_decoded_bytes": policy.max_decoded_bytes,
                },
            )
        )
    if totals.attachments > policy.max_attachments:
        violations.append(
            SecurityViolation(
                TOO_MANY_ATTACHMENTS,
                "",
                {
                    "attachments": totals.attachments,
                    "max_attachments": policy.max_attachments,
                },
            )
        )
    if totals.max_depth > policy.max_depth:
        deepest = next(
            r["path"] for r in rows if int(r["depth"]) == totals.max_depth
        )
        violations.append(
            SecurityViolation(
                MAX_DEPTH_EXCEEDED,
                deepest,
                {
                    "depth": totals.max_depth,
                    "max_depth": policy.max_depth,
                },
            )
        )

    return SecurityReport(totals=totals, violations=violations)
