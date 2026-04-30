# Structured Secret Detector V2 设计文档

## 目标

把 `privacy-filter-local` 从“以 regex backstop 为主的 secret 检测器”升级为一个 `secret-first` 的混合检测器：

- 结构化解析
- 规则候选
- 可解释打分
- 模型中度辅助

第一阶段的核心目标不是扩大无限多的 secret 类别，而是提升**边界正确性**和**结构保真**，确保在混合日志、配置片段、HTTP 头、JSON/YAML、日志句子中，优先只替换真正的 secret value，而不是吞掉整行或整句。

## 背景问题

当前实现已经能覆盖很多开发场景下的强模式 secret：

- `sk-...`
- `ghp_...`
- `github_pat_...`
- `hf_...`
- JWT
- Bearer
- session / cookie
- 带凭证的数据库连接串
- verification code / OTP / 动态口令

但当前主路径仍然是：

1. 在原始全文上做 regex 匹配
2. 产出宽松 span
3. 和 OPF 输出做合并
4. 直接按 span 做替换

这会导致几个系统性问题：

- `token = ...`、`access_token = ...`、`refresh_token = ...` 这种 `key=value` 结构容易整行被替换
- `Authorization: Bearer ...` 和 `Bearer` 内部 value 的边界不稳定
- `DATABASE_URL=` 这种左侧配置键名无法保真
- 模型输出的 span 可能过宽，吞掉整段文本
- 检测模式主要靠硬编码开关，而不是统一的置信度策略

因此，下一阶段的目标不是继续单纯堆 regex，而是把 secret 检测器升级为一个**结构优先、规则主导、模型辅助、可打分、可解释**的混合系统。

## 产品决策

该阶段延续当前的产品方向：

- `secret-first`
- 默认动作仍然是 `warn`
- 保留 PII 检测，但在 UI 和决策层是次级信号
- 保留 `High Recall / Balanced / High Precision` 三档模式

新的变化不在于页面整体交互，而在于后端 secret 检测内核升级。

## 范围

### 第一阶段必须覆盖

第一阶段结构解析器必须支持 4 类输入结构：

1. `.env / shell / INI`
2. `HTTP / Cookie / Set-Cookie`
3. `JSON / YAML`
4. `日志句子`

### 第一阶段必须实现的 secret 类型

1. API key
2. token
3. JWT
4. Bearer credential
5. cookie / session material
6. verification code / OTP / 动态口令
7. 数据库连接串
8. webhook / signing / client / app secret

### 非目标

本阶段不做：

- 远程策略中心
- 复杂规则 DSL
- 全量 provider-specific catalogue
- 图像或附件 secret 检测
- 让模型直接主导最终 secret span
- 全面替换现有 OPF / regex 逻辑

## 总体架构

V2 检测器按 5 个顺序模块运行：

1. `结构解析层`
2. `规则候选层`
3. `打分层`
4. `模型辅助层`
5. `合并与脱敏层`

### 1. 结构解析层

输入是一整段混合文本。

输出不是最终 secret span，而是一组结构化片段。每个片段至少需要具备：

- `structure_kind`
- `raw_fragment`
- `fragment_span`
- `value_span` 或 `candidate_value_span`
- 和结构相关的局部字段，例如 `key`、`separator`、`header_name`、`auth_scheme`、`context_phrase`

结构解析层的核心职责是：

- 先确定文本结构
- 只把候选 value 部分交给后续层
- 从架构上限制 span 不得越过结构边界

### 2. 规则候选层

这一层只对结构化片段中的候选 value 运行规则。

原则：

- 不优先扫整段原文
- 优先检查 `value_span`
- 把每个命中产出为候选 secret record，而不是直接生成最终输出 span

### 3. 打分层

每个候选都统一产出：

- `kind`
- `source`
- `score`
- `reason_codes`

这一步是 detection mode 从“硬编码模式开关”升级为“置信度驱动策略”的基础。

### 4. 模型辅助层

模型是中度辅助角色，不主导最终结果。

它只允许：

- `confirm`
- `narrow_boundary`
- `suggest_missing_candidate`

不允许：

- 扩展成整行 span
- 合并多个 value 成一个 secret
- 覆盖结构解析边界
- 直接替换解析层输出

### 5. 合并与脱敏层

最终 secret span 只由：

- 结构化 value 边界
- 规则命中
- 分数阈值
- 受限模型辅助

共同决定。

脱敏输出必须遵循强保真原则：

- 只替换 value
- 尽量保留原始 key、分隔符、空格、换行、注释

## 结构解析设计

### A. `.env / shell / INI`

支持：

- `KEY=value`
- `KEY = value`
- `export KEY=value`
- 单引号/双引号包裹值

解析后至少保留：

- `structure_kind="assignment"`
- `prefix`
- `key`
- `separator`
- `value`
- `quote_char`
- `line_span`
- `value_span`

示例目标：

- `OPENAI_API_KEY=sk-xxx` -> `OPENAI_API_KEY=<SECRET>`
- `token = abc` -> `token = <SECRET>`

### B. HTTP / Cookie

支持：

- `Authorization: Bearer ...`
- `Authorization: Basic ...`
- `Cookie: ...`
- `Set-Cookie: ...`

解析后至少保留：

- `header_name`
- `auth_scheme`
- `cookie_name`
- `cookie_value`
- `separator`
- `value_span`

要求：

- Bearer 只替换右侧 token
- Cookie / Set-Cookie 要按单个 cookie entry 分裂，不允许整条 header 被当成一个 secret

### C. JSON / YAML

支持：

- `"token": "abc"`
- `"client_secret": "abc"`
- `access_token: abc`
- `client_secret: abc`

解析后至少保留：

- `container_kind`
- `key` 或 `key_path`
- `separator`
- `value`
- `quote_char`
- `value_span`

要求：

- 只替换 value
- key 保持不变
- 嵌套结构第一阶段可用文本级 key/value 解析完成，不要求完整 AST

### D. 日志句子

支持：

- `verification code is 128841`
- `OTP: 556677`
- `动态口令为：882190`
- 其它带 secret 上下文的句子

解析后至少保留：

- `context_phrase`
- `candidate_value`
- `candidate_span`
- `context_span`

要求：

- 如果只定位到短码，则只替换短码
- 不允许把整句日志整体替换成 `<SECRET>`

### E. 非结构化兜底

若文本无法落入上述结构，则退回 legacy regex secret 扫描。

这个兜底是最后手段，不是主路径。

## 规则候选设计

规则层的职责是根据结构化片段提出候选，而不是决定最终输出。

### 强结构强形态候选

例如：

- `sk-...`
- `ghp_...`
- `github_pat_...`
- `hf_...`
- JWT 三段式
- `postgres://user:pass@host/db`

这类候选天然应有较高基础分。

### 强键名弱 value 候选

例如：

- `token = demo_value`
- `client_secret: demo_value`
- `DATABASE_URL=...`

这类候选依赖：

- key 名命中
- 结构命中
- value 形态中等

### 上下文短码候选

例如：

- `verification code is 128841`
- `OTP: 662211`
- `动态口令：882190`

这类候选依赖：

- context 命中
- 短值形态命中

## 打分设计

### 标准输出字段

每个候选必须带：

- `kind`
- `source`
- `score`
- `reason_codes`

### 证据来源

第一阶段至少保留这 5 类：

1. `structure_match`
2. `key_name_match`
3. `value_shape_match`
4. `context_match`
5. `model_confirmed`

### 打分原则

第一阶段使用可解释加权，不引入复杂学习型 scoring。

大方向：

- 强结构 + 强 value 形态 -> 高分
- 强 key 名 + 中等 value -> 中分
- 只有上下文短码 -> 中低分
- 只有弱词面、缺少结构支撑 -> 低分

## Detection Mode 设计

三种模式从“regex 开关”升级为“接受阈值”。

### High Recall

- 阈值最低
- 更接受弱上下文和弱形态候选
- 召回更高，误报也更高

### Balanced

- 默认模式
- 需要比较可靠的结构与 shape 组合
- 用于日常开发文本检查

### High Precision

- 阈值最高
- 强结构、强形态优先
- 低置信候选通常需要模型确认

早期迁移期间可以保留少量模式专属规则，但整体方向必须转向 score-driven。

## 模型辅助设计

### 输入边界

模型不得直接看整段原文来生成最终 secret span。

模型输入单位是 `candidate record`，至少包含：

- `structure_kind`
- `key`
- `context_phrase`
- `candidate_value`
- `candidate_value_span`
- `rule_kind`
- `reason_codes`
- `raw_fragment`

### 允许动作

1. `confirm`
2. `narrow_boundary`
3. `suggest_missing_candidate`

### 禁止动作

1. `expand_to_full_line`
2. `merge_multiple_values_into_one_secret`
3. `replace_entire_sentence`
4. `override_parser_structure`

### 输出结构

模型输出必须结构化，至少包含：

- `action`
- `confidence_delta`
- `suggested_start`
- `suggested_end`
- `extra_reason_codes`

## 合并优先级

最终 merge 规则必须体现 V2 的设计目标：

1. 精确 value span 优先于宽泛 span
2. 结构解析产出的 span 优先于 legacy 全文 regex span
3. regex secret 优先于 OPF 产生的宽泛 secret span
4. PII 仍可保留，但不能盖过 secret-first 逻辑

特别地：

- `token = ...` 不允许整行替换
- `Authorization: Bearer ...` 只替换 Bearer value
- `DATABASE_URL=postgres://...` 只替换右侧连接串
- `verification code is 128841` 只替换短码 value

## 迁移策略

### 双轨迁移

第一阶段不删除 legacy regex backstop，而是采用双轨模式：

1. 新结构化检测器运行
2. 旧 regex 检测器运行
3. 两者并行对比
4. merge 时优先保留边界更精确的结果

### 影子对比

在迁移初期，新检测器可以并行输出内部调试信息，用于和旧结果比较：

- 是否漏掉旧规则能抓到的强模式
- 是否明显改善了 value 边界
- 是否减少整行吞掉现象

## UI 影响

第一阶段不需要重做页面结构，但调试信息应允许展示更多 secret span 元数据。

建议可折叠展示：

- `kind`
- `source`
- `score`
- `reason_codes`

这样用户在手测时能直接理解：

- 为什么命中
- 为什么没命中
- 哪一层起了作用

## 测试策略

必须建立四层测试。

### 1. Parser Tests

验证每类结构是否正确产出：

- `key`
- `separator`
- `value`
- `value_span`

### 2. Detector Tests

验证在不同模式下，候选是否正确产出：

- `kind`
- `score`
- `reason_codes`

### 3. Merge Tests

验证：

- 不重复替换
- 精确 value span 优先
- 宽泛 OPF secret 不压过精确规则结果

### 4. Golden Output Tests

对完整输入断言最终 `redacted_text`。

这是第一阶段最重要的回归层。

## 回归语料

第一批固定语料至少包括：

1. `.env` 配置块
2. `Authorization/Bearer`
3. `Cookie/Set-Cookie`
4. JWT
5. `DATABASE_URL`
6. JSON 配置对象
7. YAML 配置片段
8. `verification code / OTP / 动态口令`
9. 混合日志块
10. 明确非命中样例

## 成功标准

第一阶段成功的标准是：

1. `token = secret` 不再整行吞掉
2. `Authorization: Bearer ...` 只替换右侧 value
3. `DATABASE_URL=postgres://...` 只替换右侧 value
4. `verification code is 128841` 只替换短码
5. JSON/YAML secret 字段只替换 value
6. 现有强模式 secret 无明显回退
7. 三种 detection mode 能通过统一 score 策略解释

## 已确认的设计决策

本轮已确认：

- 第一阶段按“日志/代码片段混合”场景设计
- 输出采用强保真策略
- 解析范围第一阶段覆盖 `.env/shell/INI`、`HTTP/Cookie`、`JSON/YAML`、`日志句子`
- 模型角色为“中度辅助”
- span 元数据采用 `kind + source + score + reason_codes`
- 总体路线采用 `Parser-first`

无需再补充新的产品级决策，即可进入实现计划阶段。
