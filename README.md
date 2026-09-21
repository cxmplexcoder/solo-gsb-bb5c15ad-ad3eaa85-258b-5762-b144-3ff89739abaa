# MIME 邮件归档指纹 API

接收**原始 RFC 5322 邮件**字节，递归解析 MIME 树（multipart 边界、
Content-Transfer-Encoding、字符集、RFC 2047 编码字、RFC 2231 参数），
按**规范化头字段**与**解码后的叶子内容**生成稳定 SHA-256 指纹，
并把可查询的 MIME 树存入 SQLite。

- 同一封邮件的不同换行风格（CRLF / LF / 裸 CR）、不同头字段大小写、
  不同 multipart `boundary`、不同 Content-Transfer-Encoding
  （8bit / base64 / quoted-printable）或等价字符集标注，
  **得到完全相同的指纹**；
- 损坏的边界、重复参数、无法解码的字符集 / base64 / quoted-printable
  等情况返回 **HTTP 422**，错误体带 **`node_path` 精确定位到 MIME 节点**，
  且**不会写入任何半成品数据**；
- 相同指纹重复提交是幂等的（返回同一 id，`created=false`）；
- 所有非文本叶子的解码字节进入**内容寻址附件库**（按 SHA-256 去重），
  记录每次出现的 `message_id` / `node_path` / 解码文件名 / disposition，
  支持分页检索与带 `Range` 的下载；
- `GET /messages/{id}/security-report` 对已归档 MIME 树做**确定性的
  附件安全策略评估**（双扩展名 / 控制字符文件名、禁止媒体类型、嵌套
  封装报文、解码字节 / 附件数 / 深度阈值），纯只读、可复现。

技术栈：FastAPI + SQLite（标准库 `sqlite3`，无 ORM），无第三方 MIME
解析库——解析器按 RFC 严格手工实现，刻意不使用容错的 Python `email` 包。

## 目录结构

```
app/
  main.py        FastAPI 路由与启动初始化
  mimeparser.py  严格 MIME/RFC 5322 解析、传输解码、规范化与指纹
  related.py     cid: 内嵌资源引用审计（RFC 2392，multipart/related 作用域）
  displaybody.py 展示正文选择（alternative/related/mixed 递归规则，纯只读）
  security.py    附件安全策略评估（文件名/媒体类型/嵌套报文/总量阈值，纯只读）
  database.py    SQLite 建表、事务化写入、消息/节点/附件查询
  errors.py      定位到节点的解析错误
  schemas.py     响应模型
tests/           202 个 pytest 用例（指纹稳定性、损坏输入、附件库、
                 cid 引用审计、展示正文选择、附件安全评估、HTTP 端到端）
Dockerfile
docker-compose.yml
requirements.txt
```

## 快速开始（Docker）

```bash
docker compose up --build
```

服务监听 **8000** 端口，SQLite 数据文件位于容器内 `/data/mime.db`
（compose 中以命名卷 `mime-data` 持久化）。启动时自动建库建表。

健康检查：

```bash
curl http://localhost:8000/health
# {"status":"ok","database":"/data/mime.db"}
```

## 本地运行（不用 Docker）

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
export MIME_DB_PATH=./data/mime.db   # 可选，默认 /data/mime.db
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 提交一封邮件

请求体就是邮件原始字节（建议 `Content-Type: message/rfc822`，
但服务端不依赖该头）：

```bash
curl -X POST http://localhost:8000/messages \
     -H 'Content-Type: message/rfc822' \
     --data-binary @message.eml
```

成功响应 `201`：

```json
{
  "id": 1,
  "fingerprint": "58d92498…431",
  "raw_sha256": "97d9604f…6fb",
  "content_type": "multipart/mixed",
  "size_bytes": 380,
  "created": true,
  "node_count": 3
}
```

再次提交语义相同但字节不同（换行、头大小写、boundary、CTE 不同）的邮件，
返回同一 `id` 与 `fingerprint`，`created` 为 `false`。

## 查询

| 方法 | 路径 | 说明 |
| ---- | ---- | ---- |
| GET | `/messages` | 列表（`limit`、`offset` 分页） |
| GET | `/messages/{id}` | 邮件元信息 |
| GET | `/messages/{id}/tree` | **嵌套 MIME 树** |
| GET | `/messages/{id}/nodes` | 全部节点（扁平，children 为路径） |
| GET | `/messages/{id}/nodes/{path}` | 单个节点详情（头字段、文本/二进制哈希） |
| GET | `/messages/{id}/related-resources` | 审计 HTML 对 `cid:` 内嵌资源的引用（见下） |
| GET | `/messages/{id}/display-body?prefer=html\|plain` | 选择客户端应展示的正文（见下） |
| GET | `/messages/{id}/security-report` | 附件安全策略评估（见下） |
| GET | `/attachments` | 附件库列表（分页 + `sha256`/`filename`/`media_type` 过滤） |
| GET | `/attachments/{sha256}/content` | 下载附件原始解码字节（支持单段 `bytes` Range） |

节点路径规则：根节点为 `""`，子节点为 1 基序号 `1`、`2`，
深层为 `1/2` 这样的物化路径。根节点详情用末尾斜杠：

```bash
curl http://localhost:8000/messages/1/tree
curl http://localhost:8000/messages/1/nodes/        # 根节点
curl http://localhost:8000/messages/1/nodes/2       # 第 2 部分
curl http://localhost:8000/messages/1/nodes/2/1     # 第 2 部分里的封装邮件
```

文本叶子的 `text` 是按声明字符集解码、NFC 规范化、换行统一为 `\n`
后的内容；非文本叶子不回传字节，只给 `blob_sha256` 与 `blob_length`。

## `cid:` 内嵌资源引用审计

```bash
curl http://localhost:8000/messages/1/related-resources
```

审计归档邮件 HTML 对 `multipart/related`（RFC 2387）内
`Content-ID` 资源的 `cid:` 引用：

- 从每个 **text/html 叶子** 的 `src`、`href`、`poster`、`srcset`
  属性（按 HTML 文档序，`srcset` 支持多个候选）提取 `cid:` 引用，
  按 **RFC 2392 §2 百分号解码**（如 `cid:logo%40x.com` →
  `logo@x.com`），`cid:` scheme 大小写不敏感；
- 作用域严格限定为该 HTML 叶子 **最近的 `multipart/related`
  祖先**：只在该祖先的后代中匹配 `Content-ID`，**不向相邻兄弟
  作用域、也不向内层嵌套作用域串联**（`multipart/mixed` 等其他
  容器对作用域判定透明）；
- 每条引用给出源 `source_node_path`、状态与目标：
  - `resolved` —— 作用域内唯一命中，附 `target_node_path`；
  - `missing` —— 作用域内无对应 `Content-ID`（HTML 不在任何
    related 作用域时同样判 missing，`scope_node_path` 为 `null`）；
  - `ambiguous` —— **同作用域内重复 Content-ID**，附全部
    `candidates` 节点路径（跨不同作用域的同名 ID 合法，不算歧义）；
- `scopes` 按文档序列出每个 `multipart/related` 作用域中未被本作用域
  HTML 引用的 `Content-ID` 节点（`orphans`）；
- `Content-ID` 头规范化时剥掉 RFC 2045 的一层尖括号（`"<foo>"` →
  `foo`，裸 ID 按字面接受），`cid:<foo>` 与
  `cid:%3Cfoo%3E` 也做对称容忍；
- 邮件不存在返回 **404**。

响应示例：

```json
{
  "id": 1,
  "fingerprint": "defeef89…299c40",
  "references": [
    {
      "source_node_path": "1",
      "attribute": "src",
      "cid": "logo@x.com",
      "scope_node_path": "",
      "status": "resolved",
      "target_node_path": "2",
      "candidates": []
    },
    {
      "source_node_path": "1",
      "attribute": "src",
      "cid": "missing@x.com",
      "scope_node_path": "",
      "status": "missing",
      "target_node_path": null,
      "candidates": []
    }
  ],
  "scopes": [
    {
      "node_path": "",
      "orphans": [
        {
          "node_path": "3",
          "content_type": "image/gif",
          "content_ids": ["orphan@x.com"]
        }
      ]
    }
  ]
}
```

`ambiguous` 时 `target_node_path` 为 `null`，`candidates` 列出同作用域
所有同 ID 节点；歧义候选视为“已被引用”，不会再出现在 `orphans` 中。

## 展示正文选择

```bash
curl 'http://localhost:8000/messages/1/display-body?prefer=html'
curl 'http://localhost:8000/messages/1/display-body?prefer=plain'
```

在**已归档 MIME 树**上递归选出客户端应展示的正文。该接口是**纯只读
查询**：只读取归档时保存的节点与头字段，不改写任何记录，因此对历史
归档数据同样有效（无需重新归档）。

递归选择规则（沿实际选中路径逐层进行）：

- **`multipart/alternative`**：在可展示分支中，优先选择其*实际正文*
  匹配 `prefer` 的分支——`prefer=html` 偏好 `text/html`、
  `prefer=plain` 偏好 `text/plain`，多个命中取文档序第一个；没有任何
  分支能给出偏好类型时，选择**最后一个可展示分支**（RFC 2046：备选按
  保真度从低到高排列，末位最忠实）；
- **`multipart/related`**：按容器 Content-Type 上的 **RFC 2387
  `start` 参数**匹配**直接子件**的 `Content-ID`（`start` 支持
  RFC 2231 百分号编码，尖括号做与 `cid:` 审计一致的一层容忍）；
  **未配置 `start` 时取首个子件**（RFC 2387 的缺省根部分）；
- **`multipart/mixed` 及其他 multipart 子类型**（如
  `multipart/signed` / `multipart/parallel`）：按文档序取
  **首个可展示子件**。

“可展示”指递归到一个 **text 叶子**（`kind == "text"`，含
`text/enriched` 等其他 text/*）。以下内容**不作为候选**：

- 任何 `Content-Disposition: attachment` 节点（及其整棵子树；
  `inline` 不受影响）；
- **`message/rfc822` / `message/global` 封装报文的内部正文**——封装
  容器是不向内穿透的屏障；
- 非文本叶子（内嵌图片等 `blob` 节点）。

空的 text 叶子仍是可展示正文（空正文也是正文）。`start` / 首个子件是
related 的**权威**选择：目标不可展示时不静默改选其他兄弟。未被选中的
alternative 分支即使内部含 `start` 配置错误也不阻断其他分支；当全部
分支都不可展示时，唯一路径上的配置错误会照常返回。

响应（命中时 `200`）给出最终叶子的 `node_path`、`content_type`、
`text`，以及逐层选择轨迹 `trail`：

```json
{
  "id": 1,
  "fingerprint": "defeef89…299c40",
  "prefer": "html",
  "node_path": "2/2/1",
  "content_type": "text/html",
  "text": "<p>正文</p>",
  "trail": [
    {
      "node_path": "",
      "content_type": "multipart/mixed",
      "rule": "first-displayable",
      "considered": ["1", "2"],
      "candidates": ["2"],
      "chosen": "2",
      "detail": {}
    },
    {
      "node_path": "2",
      "content_type": "multipart/alternative",
      "rule": "alternative-prefer",
      "considered": ["2/1", "2/2"],
      "candidates": ["2/1", "2/2"],
      "chosen": "2/2",
      "detail": {"prefer": "html"}
    },
    {
      "node_path": "2/2",
      "content_type": "multipart/related",
      "rule": "related-start",
      "considered": ["2/2/1", "2/2/2"],
      "candidates": ["2/2/1"],
      "chosen": "2/2/1",
      "detail": {"start": "body@x.com"}
    }
  ]
}
```

轨迹中的 `rule` 取值：

| `rule` | 含义 |
| ---- | ---- |
| `alternative-prefer` | alternative 中按 `prefer` 命中实际正文匹配的分支 |
| `alternative-fallback-last` | alternative 无偏好命中，回退最后一个可展示分支 |
| `related-start` | related 按 `start` 参数匹配 Content-ID（`detail.start`） |
| `related-first` | related 未配置 `start`，取首个子件 |
| `first-displayable` | mixed 等容器取首个可展示子件 |

每项的 `considered` 是该层实际评估过的直接子件、`candidates` 是规则下
合格的候选、`chosen` 是实际进入的子件。

异常情况：

- 邮件不存在：**404**；邮件存在但整棵树没有任何可展示正文（全是
  attachment / 封装报文 / 二进制叶子）：**404**；
- `prefer` 取值不是 `html` / `plain`：FastAPI 参数校验 **422**；
- `start` 配置错误统一为带节点定位的 **422**，`node_path` 指向出问题
  的 **multipart/related 容器**：

  | 错误码 `code` | 触发条件 |
  | ---- | ---- |
  | `AMBIGUOUS_RELATED_START` | `start` 在直接子件中重复命中 Content-ID，`detail.candidates` 给出全部命中子件路径，`detail.start` 为规范化后的 ID |
  | `RELATED_START_NOT_FOUND` | 配置了 `start` 但没有任何直接子件声明该 Content-ID（只匹配直接子件，不向内层后代串联），`detail.start` 为该 ID |

## 附件安全策略评估

```bash
curl http://localhost:8000/messages/1/security-report
curl 'http://localhost:8000/messages/1/security-report?max_attachments=5&max_depth=4'
curl 'http://localhost:8000/messages/1/security-report?forbidden_media_types=application/pdf,application/x-sh'
```

在**已归档 MIME 树**上执行确定性的附件安全策略评估。该接口是**纯只读
查询**：只读取归档时保存的节点与头字段，不修改任何记录，同一归档重复
请求得到逐字节一致的结果，对历史归档数据同样有效（无需重新归档）。

从根节点按物化路径**递归累计**三项总量（`totals`）：

- `decoded_bytes` —— 全部叶子的解码字节数：`blob` 叶子取归档时留存的
  解码长度，`text` 叶子取规范化文本的 UTF-8 编码长度；
- `attachments` —— 附件节点数：`Content-Disposition: attachment`
  **或**声明了文件名（Content-Disposition `filename` / Content-Type
  `name`，均已完成 RFC 2231 解码）的节点；
- `max_depth` —— 树的最大 MIME 深度（根为 0）。

逐节点策略检查（每次命中产生一条 violation）：

| `code` | 触发条件 |
| ---- | ---- |
| `DOUBLE_EXTENSION` | 附件文件名以两个连续 ASCII 扩展名结尾（`invoice.pdf.exe`、`archive.tar.gz` 均命中），`detail.extensions` 给出最后两个扩展名 |
| `CONTROL_CHAR_IN_FILENAME` | 文件名含 Unicode 类别 Cc（控制字符）或 Cf（格式字符，如 U+202E 反向覆盖）的字符，`detail.control_characters` 给出位置与码位 |
| `FORBIDDEN_MEDIA_TYPE` | 附件节点的媒体类型命中禁止清单 |
| `NESTED_MESSAGE` | 深度 ≥ 1 的 `message/rfc822` / `message/global` 封装报文（根节点本身是被归档的邮件，不计） |
| `DECODED_BYTES_EXCEEDED` | 解码字节总量 **严格大于** `max_decoded_bytes`（`node_path` 为根 `""`） |
| `TOO_MANY_ATTACHMENTS` | 附件数量严格大于 `max_attachments`（`node_path` 为根 `""`） |
| `MAX_DEPTH_EXCEEDED` | MIME 深度严格大于 `max_depth`（`node_path` 定位最深节点） |

任一 violation 命中即 `allow=false`，否则 `allow=true`。violation 顺序
确定：先按文档序逐节点输出，再按字节数、附件数、深度的固定顺序输出阈值
违规。响应示例（命中时）：

```json
{
  "id": 1,
  "fingerprint": "defeef89…299c40",
  "allow": false,
  "limits": {
    "max_decoded_bytes": 10000000,
    "max_attachments": 20,
    "max_depth": 10,
    "forbidden_media_types": ["application/x-msdownload", "…"]
  },
  "totals": {"decoded_bytes": 51, "attachments": 1, "max_depth": 1},
  "violations": [
    {
      "code": "DOUBLE_EXTENSION",
      "node_path": "2",
      "detail": {"filename": "invoice.pdf.exe", "extensions": ["pdf", "exe"]}
    }
  ]
}
```

阈值与禁止清单均可由查询参数覆盖默认值（`limits` 回显本次实际生效的
策略）：

| 查询参数 | 默认 | 说明 |
| ---- | ---- | ---- |
| `max_decoded_bytes` | `10000000` | 解码字节总量上限（非负整数） |
| `max_attachments` | `20` | 附件节点数量上限（非负整数） |
| `max_depth` | `10` | MIME 树最大深度上限（非负整数） |
| `forbidden_media_types` | 常见可执行类型清单 | 逗号分隔的 `type/subtype` 清单，**提供时整体替换**默认清单（大小写不敏感） |

默认禁止清单：`application/x-msdownload`、`application/x-msdos-program`、
`application/x-dosexec`、`application/x-executable`、
`application/vnd.microsoft.portable-executable`、`application/x-bat`、
`application/x-sh`。

异常情况：邮件不存在返回 **404**；参数非法（负数、非整数、非法媒体
类型等）返回 **422**——请求形状错误优先于资源缺失，即邮件不存在且
参数非法时同样返回 422。

## 内容寻址附件库

归档时，所有**非文本叶子**（`kind == "blob"`，含整封邮件本身就是二进制、
以及 `message/rfc822` 封装报文内部的附件）的**解码后字节**按 SHA-256
去重存入 `attachments` 表；每次出现（哪封邮件的哪个节点、解码后的文件名、
disposition、媒体类型）记入 `attachment_refs` 表。消息、节点、附件实体
与引用在**同一事务**提交；重复归档同一指纹的邮件不会新增任何实体或引用。

- 同一内容在同一封邮件出现多次、或出现在多封邮件中，只存一份字节，
  `reference_count` 与 `occurrences` 反映全部出现位置；
- 解码文件名取 `Content-Disposition` 的 `filename`（含 RFC 2231
  `filename*=` 形式），缺省时回退 `Content-Type` 的 `name`；
- 新表用 `CREATE TABLE IF NOT EXISTS` 建立，启动时对已有 SQLite 库
  幂等升级；升级前归档的邮件未留存附件字节，不会回溯补录。

### 检索

```bash
curl 'http://localhost:8000/attachments?limit=20&offset=0'
curl 'http://localhost:8000/attachments?sha256=c1e372ae'      # 哈希前缀（完整 64 位即精确）
curl 'http://localhost:8000/attachments?filename=发票'         # 文件名子串（ASCII 大小写不敏感）
curl 'http://localhost:8000/attachments?media_type=image/png' # 出现位置的媒体类型
```

每个列表项：

```json
{
  "sha256": "c1e372ae…8001",
  "size_bytes": 45,
  "media_type": "image/png",
  "reference_count": 2,
  "created_at": "2026-09-21T03:06:15.676328+00:00",
  "occurrences": [
    {"message_id": 2, "node_path": "2", "filename": "s.png",
     "disposition": "attachment", "media_type": "image/png"},
    {"message_id": 5, "node_path": "1/2", "filename": "copy.png",
     "disposition": "attachment", "media_type": "image/png"}
  ]
}
```

`media_type`（实体级）为首次归档时的媒体类型；`filename` / `media_type`
过滤按**任一出现位置**匹配。

### 下载

```bash
curl -O http://localhost:8000/attachments/c1e372ae…/content
curl -H 'Range: bytes=0-99'  http://localhost:8000/attachments/c1e372ae…/content   # 206
curl -H 'Range: bytes=100-'  http://localhost:8000/attachments/c1e372ae…/content   # 206
curl -H 'Range: bytes=-50'   http://localhost:8000/attachments/c1e372ae…/content   # 206（最后 50 字节）
```

- 不带 `Range`：`200` 返回完整解码字节，`Content-Type` 为实体媒体类型，
  响应带 `Accept-Ranges: bytes`；
- 合法单段范围：`206` + `Content-Range: bytes start-end/size`，
  末端超出大小按 RFC 7233 收敛；
- 越界、多段（`bytes=0-1,3-4`）或非法范围：`416` +
  `Content-Range: bytes */size`；
- 未知哈希：`404`。

## 错误响应

所有解析 / 解码失败统一为 `422`：

```json
{
  "error": {
    "code": "UNDECODABLE_CONTENT",
    "message": "base64 内容含非法字符 0x40",
    "node_path": "2",
    "detail": {"offset": 0, "byte": 64}
  }
}
```

`node_path` 指向出问题的 MIME 节点（根节点为 `""`）。解析在写库之前
**完整完成**，因此失败请求不会在 `messages` / `nodes` / `attachments` /
`attachment_refs` 表中留下任何行；写库本身也在单事务内，中途出错整体回滚。

错误码：

| `code` | 触发条件 |
| ---- | ---- |
| `INVALID_MESSAGE` / `INVALID_HEADER` / `INVALID_HEADER_NAME` | 报文/头块结构不合法 |
| `DUPLICATE_HEADER` | Content-Type / CTE / Content-Disposition 重复出现 |
| `INVALID_CONTENT_TYPE` / `INVALID_DISPOSITION` | 媒体类型或 disposition 非法 |
| `INVALID_BOUNDARY` | 缺 boundary、边界非法、正文中找不到边界、缺闭合边界 |
| `DUPLICATE_PARAMETER` | 同名参数重复（含 RFC 2231 续片序号重复、普通/扩展混用） |
| `INVALID_PARAMETER` | RFC 2231 续片序号不连续、扩展值损坏 |
| `INVALID_HEADER_VALUE` | 参数引号未闭合、结构头中出现 encoded-word 等 |
| `UNKNOWN_CHARSET` | 声明的字符集无法识别 |
| `INVALID_CTE` / `UNSUPPORTED_CTE` | 传输编码非法或不支持 |
| `UNDECODABLE_CONTENT` | base64 / quoted-printable / 字符集解码失败，或 7bit 含非 ASCII 字节 |
| `UNDECODABLE_HEADER` | RFC 2047 编码字（B/Q）本身损坏 |
| `AMBIGUOUS_RELATED_START` / `RELATED_START_NOT_FOUND` | `display-body` 查询时 multipart/related 的 `start` 重复命中或未命中（查询期错误，不改写记录） |

## 指纹规范化规则

指纹输入是一棵 JSON 规范树（键排序、无多余空白、UTF-8、LF），
对其取 SHA-256。规范化时**剔除打包/传输噪音**：

- 头名统一小写；头值完成 RFC 2047 解码、Unicode NFC、线性空白压缩，
  相邻 encoded-word 之间的空白按 RFC 删除；
- 叶子文本按声明字符集解码为 Unicode，再 NFC、换行（CRLF/CR/LF）归一为 `\n`；
- 不纳入指纹：multipart `boundary`、文本节点的 `charset`（已解码）、
  Content-Transfer-Encoding（已解码）、头折叠方式、邮件换行风格；
- 非文本叶子取**解码后字节**的 SHA-256 与长度；
- 节点顺序、媒体类型、`Content-Disposition` 及其文件名等参数仍参与指纹
  （调换 part 顺序会得到不同指纹）。

可以用 `app.mimeparser` 直接查看规范化结果：

```python
from app.mimeparser import parse_message, fingerprint, canonical_tree, canonical_json
tree = parse_message(open("message.eml", "rb").read())
fp, canon = fingerprint(tree)
print(fp)
print(canon.decode())
```

## 运行测试

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

## 环境变量

| 变量 | 默认 | 说明 |
| ---- | ---- | ---- |
| `MIME_DB_PATH` | `/data/mime.db` | SQLite 文件路径，启动时自动建库建表 |

## 设计说明与边界

- **严格而非容错**：不使用 Python 标准库 `email` 包。标准库会修复坏边界、
  吞掉非法字节、对重复参数“后者覆盖”，不适合需要可复现指纹的归档场景。
- **字面头字节宽容**：非 encoded-word 的“脏”头（如老式 latin-1 Subject）
  按 UTF-8 → latin-1 回退解码，不会因此拒收邮件；编码字本身仍严格校验。
- **7bit 语义**：保留“内容仅 US-ASCII”这一不变量，但不强制 CRLF 配对，
  以支持换行风格无关的指纹。
- **epilogue / preamble**：multipart 前导区与闭合边界后的尾注按 RFC 忽略，
  不参与指纹。
- `message/rfc822` 与 `message/global` 容器递归解析；容器自身的 CTE
  先还原再递归。
