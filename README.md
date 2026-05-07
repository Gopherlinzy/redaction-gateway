# Redaction Gateway

本地脱敏网关。在文本发送到 AI 模型、聊天界面或文件外发之前，检测并脱敏 API 密钥、密码和个人信息（PII）。

## 快速开始

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m uvicorn app:app --host 127.0.0.1 --port 7861
```

说明：
- Python 3.13+ / 3.14 可以完成基础安装并运行服务
- 文本型 PDF 走 `pdftotext -bbox-layout` + PyMuPDF 的本地抽取链路
- 扫描件 / 图像型 PDF 会尝试调用仓库内置的 macOS Vision helper；当前主服务本身不再依赖额外 Python OCR wheel

访问 `http://127.0.0.1:7861/` 打开 UI。

## 运行测试

```bash
./.venv/bin/python -m pytest -v
```

133 个测试，覆盖网关路由、策略层、正则检测、结构解析、OPF 运行时、文件脱敏。

## API 路由

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 存活检查 |
| GET | `/ready` | 就绪检查（OPF 模型未加载时返回 503） |
| GET | `/stats` | 运行时缓存与请求耗时指标 |
| POST | `/scan` | 检测 span，返回风险等级 |
| POST | `/decide` | 检测 + 策略决策 |
| POST | `/redact` | 检测 + 返回脱敏文本 |
| POST | `/redact-file` | 检测文件（PDF/DOCX），返回 span 元数据 |
| POST | `/redact-file/download` | 返回脱敏后的原格式文件 |

文本路由请求体：

```json
{
  "text": "...",
  "source": "manual_ui",
  "target": "ai_model",
  "mode": "warn",
  "detection_mode": "balanced"
}
```

`/redact-file` 和 `/redact-file/download` 接受 `multipart/form-data`，包含 `file` 字段（PDF 或 DOCX）及上述其他字段。`/redact-file/download` 额外支持 `active_categories`（JSON 数组字符串），控制哪些类别参与脱敏，未选中的类别保留原文输出。

有效值：
- `source`: `manual_ui`, `symphony_prompt`, `symphony_handoff`, `linear_comment`
- `target`: `ai_model`, `linear`, `local_review`
- `detection_mode`: `balanced`, `strict`, `permissive`

## UI 功能

- **文本模式**：粘贴文本 → 扫描 → 查看左侧高亮原文 / 右侧选择性脱敏输出 → 复制
- **文件模式**：上传 PDF 或 DOCX → 扫描 → 并排查看原始文件 ↔ 脱敏文件预览 → 下载
- **统计面板**：PII 占比、span 数量、类别色块分布
- **类别 Toggle**：按类别开关脱敏；关闭后该类别原文保留在输出与下载结果中
- **单 Span 点击**：在输入高亮面板中点击单个 span 独立切换其脱敏状态
- **Inspector**：Risk / Detections / Runtime 三标签页

## 检测架构

每次请求并行运行三层检测，结果合并后交给策略层：

```
文本输入
  ├── 层 1：OPF 语义模型（openai/privacy-filter）  → 检测 PII（姓名、地址、邮箱等）
  ├── 层 2：结构解析器 + 评分器                     → 精确提取结构化密钥值
  └── 层 3：正则兜底                                → 基于模式匹配的安全网
        ↓
  merge_spans()  优先级：parser_rule > regex > opf
        ↓
  policy.decide_action() → allow / warn / redact / block
```

**层 1 — OPF 语义模型**（`detectors/opf_runtime.py`）：神经 NER 模型，SHA-256 LRU 缓存（32 条），原始文本不持久化。OPF 不可用时静默降级，PII 检测失效。

**层 2 — 结构解析器**（`detectors/structured_parser.py` → `secret_candidates.py`）：逐行解析 env 赋值、HTTP 头、Cookie、JSON/YAML 键值对、日志句子，只提取密钥值的精确 span。

**层 3 — 正则兜底**（`detectors/regex_backstop.py`）：全文匹配已知密钥形状，同时包含中国 PII 正则（身份证、护照、手机号、邮箱、公积金账号）。

## 密钥检测规则

| 类型 | 触发条件 | 置信度 |
|------|---------|--------|
| `api_key`（OpenAI/GitHub/AWS/HuggingFace/Slack/Stripe） | 前缀 + 长度/字符集校验 | 0.90 |
| `jwt` | `eyJ...` 三段 base64url + header 解码含 `alg` | 0.90 |
| `bearer` | `Authorization: Bearer <val>` | 0.80 |
| `db_connection` | `postgres/mysql/mongodb://user:PASS@host` | 0.90 |
| `private_key` | PEM 块 `-----BEGIN ... PRIVATE KEY-----` | 0.95 |
| `session` | Cookie：sessionid/session/connect.sid | 0.80 |
| `token` | 白名单键名 + 高熵值 ≥12 位 | 0.75 |
| `webhook_secret` / `oauth_code` / `aws_signature` | 结构模式 | 0.80–0.90 |
| `verification_code` | OTP 触发短语 + 4–10 位代码 | 0.65 |
| PII（邮箱/手机/姓名/地址/日期/账号） | OPF 语义模型 | 模型分数 |

## 文件脱敏

- **PDF**：优先使用 `pdftotext -bbox-layout` 抽取文本和坐标；扫描件/图像型 PDF 会尝试走本地 Vision OCR。下载时优先使用抽取阶段得到的字符坐标做定点黑块覆盖；若 OCR 坐标不可用，则不会猜测 bbox
- **DOCX**：在 run 级别替换匹配文字为 `<REDACTED>`

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PRIVACY_FILTER_PREWARM_ON_STARTUP` | `1` | 设为 `0` 跳过启动时 OPF 模型预热 |
| `PRIVACY_FILTER_TIMING_LOGS` | `0` | 设为 `1` 开启每次请求耗时日志 |
| `PRIVACY_FILTER_DEVICE` | `cpu` | 设为 `cuda` 使用 GPU 推理 |

## 已知局限

- **OPF 不可用**：邮箱、手机、姓名、地址检测失效，无正则兜底
- **扫描件 OCR 受宿主环境限制**：文本型 PDF 不受影响；扫描件 PDF 依赖本地 Vision helper 是否可在当前 macOS/沙箱环境中执行成功
- **OCR PDF 下载保真有限**：OCR 提升的是检测与 review 文本质量；若 PDF 本身没有可靠文本层，本阶段下载文件不会猜测 bbox 去画黑块
- **OCR 速度慢于文本层**：扫描件/图像型 PDF 会比普通可选中文本 PDF 更慢
- **`detection_mode` strict/permissive**：均映射到 `balanced`，三档未完全接入
- **YAML 块标量**（`|` / `>` 多行）：单行解析器无法跨行
- **Azure SAS token / Google Cloud 服务账号 JSON**：无覆盖
- `adapters/` 目录（`linear.py`、`symphony.py`）为预留存根，路由尚未接入

## 设计约束

- 服务只绑定 `127.0.0.1`，不对外暴露
- 原始文本不持久化（缓存只存位置偏移量）
- OPF 模型首次使用时下载到 `~/.opf/privacy_filter`
- `policy.py` 是纯决策层，不含任何检测逻辑
