"""附件安全策略评估（GET /messages/{id}/security-report）测试。

覆盖：
* 干净邮件 allow=true、totals（解码字节/附件数/深度）精确累计；
* 文件名双扩展名（含 .tar.gz、单扩展名不命中、Content-Type name 回退）；
* 文件名控制字符（RFC 2231 百分号编码、quoted-string 字面 TAB、
  Cf 格式字符 U+202E）；
* 禁止媒体类型（默认清单、查询参数整体覆盖、非法清单 422）；
* 嵌套 message/rfc822 与 message/global（根节点自身不计）；
* 三项阈值（严格大于才违规、查询参数覆盖默认值、非法参数 422）；
* 404、重复请求结果稳定、纯只读不改库、violation 顺序确定。
"""

import base64

from conftest import make_multipart, text_part

PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(32))  # 40 字节
PDF = b"%PDF-1.4 fake" * 3  # 39 字节


# ---------------------------------------------------------------------------
# 构造辅助
# ---------------------------------------------------------------------------


def bin_part(
    data: bytes,
    *,
    ctype: str = "application/octet-stream",
    name: str | None = None,
    disposition: str | None = "attachment",
    filename: str | None = None,
    cte: str | None = "base64",
) -> bytes:
    """构造一个非文本叶子部分（默认 base64 编码的附件）。"""

    ct = f"Content-Type: {ctype}"
    if name is not None:
        ct += f'; name="{name}"'
    lines = [ct]
    if disposition is not None:
        disp = f"Content-Disposition: {disposition}"
        if filename is not None:
            disp += f'; filename="{filename}"'
        lines.append(disp)
    if cte is not None:
        lines.append(f"Content-Transfer-Encoding: {cte}")
    head = "\r\n".join(lines).encode() + b"\r\n\r\n"
    body = base64.b64encode(data) if cte == "base64" else data
    return head + body


def rfc822_part(inner: bytes, *, ctype: str = "message/rfc822") -> bytes:
    return f"Content-Type: {ctype}\r\n\r\n".encode() + inner


def message_with_parts(*parts: bytes, subject: str = "sec test") -> bytes:
    return (
        f"Subject: {subject}\r\n".encode()
        + b"Content-Type: multipart/mixed; boundary=MIX\r\n\r\n"
        + make_multipart(list(parts), "MIX")
    )


def post(client, data: bytes) -> int:
    r = client.post("/messages", content=data)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def report(client, mid: int, query: str = "", **params) -> dict:
    r = client.get(f"/messages/{mid}/security-report{query}", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def codes(body: dict) -> list[str]:
    return [v["code"] for v in body["violations"]]


# ---------------------------------------------------------------------------
# 干净邮件与 totals 累计
# ---------------------------------------------------------------------------


def test_clean_message_allow_true_and_totals(client):
    mid = post(
        client,
        message_with_parts(
            text_part("plain body"),
            bin_part(PNG, ctype="image/png", filename="a.png"),
        ),
    )
    body = report(client, mid)
    assert body["id"] == mid
    assert body["fingerprint"] == client.get(f"/messages/{mid}").json()[
        "fingerprint"
    ]
    assert body["allow"] is True
    assert body["violations"] == []
    # 文本叶子按规范化文本的 UTF-8 长度计，blob 取留存的解码长度
    assert body["totals"] == {
        "decoded_bytes": len("plain body".encode("utf-8")) + len(PNG),
        "attachments": 1,
        "max_depth": 1,
    }
    # 默认阈值与默认禁止清单原样回显
    assert body["limits"]["max_decoded_bytes"] == 10_000_000
    assert body["limits"]["max_attachments"] == 20
    assert body["limits"]["max_depth"] == 10
    assert "application/x-msdownload" in body["limits"][
        "forbidden_media_types"
    ]


def test_text_only_root_message(client):
    mid = post(
        client,
        b"Subject: hi\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhello",
    )
    body = report(client, mid)
    assert body["allow"] is True
    assert body["totals"] == {
        "decoded_bytes": 5,
        "attachments": 0,
        "max_depth": 0,
    }


def test_non_ascii_text_counted_as_utf8(client):
    # 8bit CTE：非 ASCII 内容按 UTF-8 解码后以其 UTF-8 长度计入
    mid = post(client, message_with_parts(text_part("你好", cte="8bit")))
    body = report(client, mid)
    assert body["totals"]["decoded_bytes"] == len("你好".encode("utf-8"))
    assert body["allow"] is True


def test_attachment_without_filename_counts_but_clean(client):
    mid = post(
        client,
        message_with_parts(bin_part(PNG, ctype="image/png")),  # 无文件名
    )
    body = report(client, mid)
    assert body["totals"]["attachments"] == 1
    assert body["allow"] is True


def test_inline_with_filename_counts_as_attachment(client):
    mid = post(
        client,
        message_with_parts(
            bin_part(PNG, ctype="image/png", disposition="inline",
                     filename="pic.png"),
        ),
    )
    body = report(client, mid)
    assert body["totals"]["attachments"] == 1
    assert body["allow"] is True


# ---------------------------------------------------------------------------
# 文件名：双扩展名
# ---------------------------------------------------------------------------


def test_double_extension_filename(client):
    mid = post(
        client,
        message_with_parts(bin_part(PDF, filename="invoice.pdf.exe")),
    )
    body = report(client, mid)
    assert body["allow"] is False
    assert body["violations"] == [
        {
            "code": "DOUBLE_EXTENSION",
            "node_path": "1",
            "detail": {
                "filename": "invoice.pdf.exe",
                "extensions": ["pdf", "exe"],
            },
        }
    ]


def test_double_extension_tar_gz_flagged_single_extension_ok(client):
    mid = post(
        client,
        message_with_parts(
            bin_part(PDF, filename="archive.tar.gz"),
            bin_part(PNG, ctype="image/png", filename="photo.png"),
        ),
    )
    body = report(client, mid)
    assert [
        (v["code"], v["node_path"]) for v in body["violations"]
    ] == [("DOUBLE_EXTENSION", "1")]
    assert body["violations"][0]["detail"]["extensions"] == ["tar", "gz"]


def test_double_extension_via_content_type_name_fallback(client):
    mid = post(
        client,
        message_with_parts(
            bin_part(PDF, name="evil.scr.exe", disposition=None),
        ),
    )
    body = report(client, mid)
    assert codes(body) == ["DOUBLE_EXTENSION"]
    assert body["violations"][0]["detail"]["filename"] == "evil.scr.exe"


# ---------------------------------------------------------------------------
# 文件名：控制字符
# ---------------------------------------------------------------------------


def test_control_char_in_filename_via_rfc2231(client):
    part = (
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment;"
        b" filename*=utf-8''evil%09name.txt\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        + base64.b64encode(PDF)
    )
    mid = post(client, message_with_parts(part))
    body = report(client, mid)
    assert body["allow"] is False
    assert body["violations"] == [
        {
            "code": "CONTROL_CHAR_IN_FILENAME",
            "node_path": "1",
            "detail": {
                "filename": "evil\tname.txt",
                "control_characters": [
                    {"position": 4, "codepoint": "U+0009", "category": "Cc"}
                ],
            },
        }
    ]


def test_control_char_in_quoted_filename(client):
    part = (
        b"Content-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="a\tb.bin"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        + base64.b64encode(PDF)
    )
    mid = post(client, message_with_parts(part))
    body = report(client, mid)
    assert codes(body) == ["CONTROL_CHAR_IN_FILENAME"]
    chars = body["violations"][0]["detail"]["control_characters"]
    assert chars == [{"position": 1, "codepoint": "U+0009", "category": "Cc"}]


def test_format_char_u202e_in_filename(client):
    # U+202E RIGHT-TO-LEFT OVERRIDE：经典文件名伪装手法，类别 Cf
    part = (
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment;"
        b" filename*=utf-8''inv%E2%80%AEoice.exe\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        + base64.b64encode(PDF)
    )
    mid = post(client, message_with_parts(part))
    body = report(client, mid)
    assert codes(body) == ["CONTROL_CHAR_IN_FILENAME"]
    detail = body["violations"][0]["detail"]
    assert detail["filename"] == "inv‮oice.exe"
    assert detail["control_characters"] == [
        {"position": 3, "codepoint": "U+202E", "category": "Cf"}
    ]


# ---------------------------------------------------------------------------
# 禁止媒体类型
# ---------------------------------------------------------------------------


def test_forbidden_media_type_default_list(client):
    mid = post(
        client,
        message_with_parts(
            bin_part(PDF, ctype="application/x-msdownload",
                     filename="setup.exe"),
        ),
    )
    body = report(client, mid)
    assert body["allow"] is False
    assert body["violations"] == [
        {
            "code": "FORBIDDEN_MEDIA_TYPE",
            "node_path": "1",
            "detail": {"media_type": "application/x-msdownload"},
        }
    ]


def test_forbidden_media_type_on_root_blob(client):
    msg = (
        b"Content-Type: application/x-msdownload\r\n"
        b'Content-Disposition: attachment; filename="setup.exe"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        + base64.b64encode(PDF)
    )
    mid = post(client, msg)
    body = report(client, mid)
    assert [
        (v["code"], v["node_path"]) for v in body["violations"]
    ] == [("FORBIDDEN_MEDIA_TYPE", "")]
    assert body["totals"]["attachments"] == 1
    assert body["totals"]["max_depth"] == 0


def test_forbidden_media_types_override_replaces_default(client):
    mid = post(
        client,
        message_with_parts(
            bin_part(PDF, ctype="application/pdf", filename="doc.pdf"),
            bin_part(PDF, ctype="application/x-msdownload",
                     filename="setup.exe"),
        ),
    )
    # 覆盖后默认清单不再生效：x-msdownload 放行、application/pdf 命中
    body = report(client, mid, forbidden_media_types="Application/PDF")
    assert body["limits"]["forbidden_media_types"] == ["application/pdf"]
    assert body["violations"] == [
        {
            "code": "FORBIDDEN_MEDIA_TYPE",
            "node_path": "1",
            "detail": {"media_type": "application/pdf"},
        }
    ]


def test_forbidden_media_types_invalid_422(client):
    mid = post(client, message_with_parts(text_part("hi")))
    for bad in (
        "not-a-type",
        "application/",
        "/pdf",
        "application/pdf,,application/x-sh",
        "application/pdf;q=1",
        "",
    ):
        r = client.get(
            f"/messages/{mid}/security-report",
            params={"forbidden_media_types": bad},
        )
        assert r.status_code == 422, bad


# ---------------------------------------------------------------------------
# 嵌套封装报文
# ---------------------------------------------------------------------------


def _inner_message() -> bytes:
    return (
        b"Subject: inner\r\n"
        b"Content-Type: multipart/mixed; boundary=IN\r\n\r\n"
        + make_multipart(
            [text_part("inner body"), bin_part(PDF, filename="deep.pdf")],
            "IN",
        )
    )


def test_nested_rfc822_message_flagged(client):
    mid = post(
        client,
        message_with_parts(text_part("outer"), rfc822_part(_inner_message())),
    )
    body = report(client, mid)
    assert body["allow"] is False
    assert body["violations"] == [
        {
            "code": "NESTED_MESSAGE",
            "node_path": "2",
            "detail": {"content_type": "message/rfc822", "depth": 1},
        }
    ]
    # 嵌套报文内部的附件与字节照常递归累计
    assert body["totals"] == {
        "decoded_bytes": len("outer") + len("inner body") + len(PDF),
        "attachments": 1,
        "max_depth": 3,
    }


def test_nested_message_global_flagged(client):
    inner = b"Subject: i\r\nContent-Type: text/plain\r\n\r\nhi"
    mid = post(
        client,
        message_with_parts(rfc822_part(inner, ctype="message/global")),
    )
    body = report(client, mid)
    assert body["violations"] == [
        {
            "code": "NESTED_MESSAGE",
            "node_path": "1",
            "detail": {"content_type": "message/global", "depth": 1},
        }
    ]


def test_root_level_rfc822_is_not_nested(client):
    inner = b"Subject: i\r\nContent-Type: text/plain\r\n\r\nhello"
    mid = post(client, b"Content-Type: message/rfc822\r\n\r\n" + inner)
    body = report(client, mid)
    assert "NESTED_MESSAGE" not in codes(body)
    assert body["allow"] is True
    assert body["totals"]["max_depth"] == 1


# ---------------------------------------------------------------------------
# 总量阈值（严格大于才违规，查询参数覆盖默认值）
# ---------------------------------------------------------------------------


def test_decoded_bytes_threshold(client):
    mid = post(
        client,
        message_with_parts(
            text_part("plain body"),
            bin_part(PNG, ctype="image/png", filename="a.png"),
        ),
    )
    total = len("plain body".encode()) + len(PNG)  # 50

    ok = report(client, mid, max_decoded_bytes=total)
    assert ok["allow"] is True
    assert ok["limits"]["max_decoded_bytes"] == total

    over = report(client, mid, max_decoded_bytes=total - 1)
    assert over["allow"] is False
    assert over["violations"] == [
        {
            "code": "DECODED_BYTES_EXCEEDED",
            "node_path": "",
            "detail": {
                "decoded_bytes": total,
                "max_decoded_bytes": total - 1,
            },
        }
    ]


def test_attachments_threshold(client):
    mid = post(
        client,
        message_with_parts(
            bin_part(PNG, ctype="image/png", filename="a.png"),
            bin_part(PDF, filename="b.pdf"),
        ),
    )
    ok = report(client, mid, max_attachments=2)
    assert ok["allow"] is True

    over = report(client, mid, max_attachments=1)
    assert over["violations"] == [
        {
            "code": "TOO_MANY_ATTACHMENTS",
            "node_path": "",
            "detail": {"attachments": 2, "max_attachments": 1},
        }
    ]


def test_depth_threshold(client):
    inner_mixed = (
        b"Content-Type: multipart/mixed; boundary=IN2\r\n\r\n"
        + make_multipart([text_part("deep")], "IN2")
    )
    outer = (
        b"Subject: depth\r\n"
        b"Content-Type: multipart/mixed; boundary=OUT\r\n\r\n"
        + make_multipart([inner_mixed], "OUT")
    )
    mid = post(client, outer)

    ok = report(client, mid, max_depth=2)
    assert ok["allow"] is True
    assert ok["totals"]["max_depth"] == 2

    over = report(client, mid, max_depth=1)
    assert over["violations"] == [
        {
            "code": "MAX_DEPTH_EXCEEDED",
            "node_path": "1/1",  # 最深节点
            "detail": {"depth": 2, "max_depth": 1},
        }
    ]


def test_invalid_threshold_params_422(client):
    mid = post(client, message_with_parts(text_part("hi")))
    for query in (
        "?max_decoded_bytes=-1",
        "?max_attachments=-1",
        "?max_depth=-1",
        "?max_depth=abc",
        "?max_decoded_bytes=1.5",
        "?max_attachments=",
    ):
        r = client.get(f"/messages/{mid}/security-report{query}")
        assert r.status_code == 422, query


# ---------------------------------------------------------------------------
# violation 顺序、确定性、只读
# ---------------------------------------------------------------------------


def test_violations_order_node_then_threshold(client):
    mid = post(
        client,
        message_with_parts(
            bin_part(PDF, filename="a.pdf.exe"),
            bin_part(PDF, ctype="application/x-bat", filename="b.bat"),
        ),
    )
    body = report(client, mid, max_decoded_bytes=1)
    assert codes(body) == [
        "DOUBLE_EXTENSION",  # 节点 1（文档序在前）
        "FORBIDDEN_MEDIA_TYPE",  # 节点 2
        "DECODED_BYTES_EXCEEDED",  # 阈值违规排在节点级之后
    ]
    assert [v["node_path"] for v in body["violations"]] == ["1", "2", ""]


def test_repeat_requests_are_byte_identical(client):
    mid = post(
        client,
        message_with_parts(
            bin_part(PDF, filename="a.pdf.exe"),
            rfc822_part(_inner_message()),
        ),
    )
    url = f"/messages/{mid}/security-report?max_depth=1&max_attachments=0"
    r1 = client.get(url)
    r2 = client.get(url)
    assert r1.status_code == r2.status_code == 200
    assert r1.content == r2.content
    assert r1.json()["allow"] is False


def test_evaluation_is_read_only(client):
    mid = post(
        client,
        message_with_parts(
            bin_part(PDF, ctype="application/x-msdownload",
                     filename="setup.exe"),
        ),
    )
    before = {
        "messages": client.get("/messages").json(),
        "nodes": client.get(f"/messages/{mid}/nodes").json(),
        "attachments": client.get("/attachments").json(),
    }
    r = client.get(f"/messages/{mid}/security-report?max_attachments=0")
    assert r.status_code == 200
    assert r.json()["allow"] is False
    after = {
        "messages": client.get("/messages").json(),
        "nodes": client.get(f"/messages/{mid}/nodes").json(),
        "attachments": client.get("/attachments").json(),
    }
    assert before == after


# ---------------------------------------------------------------------------
# 404 与参数校验优先级
# ---------------------------------------------------------------------------


def test_message_not_found_404(client):
    r = client.get("/messages/999/security-report")
    assert r.status_code == 404


def test_invalid_param_rejected_even_when_message_missing(client):
    # 请求形状错误（422）优先于资源缺失（404）
    r = client.get(
        "/messages/999/security-report",
        params={"forbidden_media_types": "bad"},
    )
    assert r.status_code == 422
    r2 = client.get("/messages/999/security-report?max_depth=abc")
    assert r2.status_code == 422
