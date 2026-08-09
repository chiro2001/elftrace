# elftrace 普通 load 值回放第三轮建议

## 结论（约 300 字）

首先不要把 `usedpools` 的首个变化事件直接解释为录制首分配：事件是按站点做的 `{addr,value}` 游程，只有原始 `event.ord == from_ord + 1`，56B 才真是录制第一命中；否则首读应由检查点合成段提供，56B 属于后续分配。若该等式成立，最可疑的上游不是 allocator，而是 `poll/ppoll` 的内存返回值，尤其 `pollfd.revents`（常由 `ldrh/ldrsh` 读取）；`x0=1` 只能证明就绪数量，不能证明每个 fd 的事件位和由其构造的 Python 结果一致。先从 record 66 的入口参数和写差分重建 pollfd 数组，在 syscall 返回点、poll 包装层出口、首个 malloc 三处做语义断点比对。站点选择以“分歧探针差分”为主，手工反向枚举用于播种；census 的 PEEKDATA 判错应顺手修，但页级首 fault 不足以判因。普通 load 的 `ord-from_ord` 本身正确，不过同为 start=1 的合成段与首事件存在脆弱重叠，建议显式去重并补边界测试。

## 1. 最可能的上游读取及无逐指令单步定位法

### 1.1 先验证“56B 是录制首分配”这个前提

记录跳板只在地址或值变化时写事件，所以 `events.bin` 不是每次 load 的日志。对发生 miss 的 `usedpools` 站点，先打印以下原始量：

- `from_ord`、`from_addr`、`from_val`；
- 窗口内该站点第一个原始事件的 `ord/addr/value`；
- 切片 miss 时的 replay ordinal、实际有效地址、当前 cursor 和当前 run；
- `first_event.ord - from_ord`。

解释规则如下：

| 条件 | 录制窗口第 1 次访问应使用的段 | 能否据首事件推断首分配尺寸 |
|---|---|---|
| 首事件相对序号为 1 | 首事件覆盖 start=1 的合成段 | 可以，地址类就是录制首命中 |
| 首事件相对序号大于 1 | 合成段覆盖 `[1, first_event_rel)` | 不可以，首事件是更晚的变化 |
| 窗口内无事件 | 不 patch，执行真实 load | 首值与检查点 last pair 相同 |

这项核对成本最低，而且可能直接推翻“48B vs 56B 是同一次 list iterator 分配”的前提。CPython 的同一个 `list_iterator` 类型，其 `tp_basicsize` 在同一进程中不会在 48/56 之间动态变化；若调用链和类型指针确实相同，尺寸不同更像是分配流错位、事件对齐误读，或更早的一次分配被跳过，而不是 `usedpools` 自己算错尺寸。

### 1.2 若相对序号确为 1，首查 poll 的内存输出

首要候选是 `pollfd.revents`，其次是 poll 包装层据此构造的结果 list/tuple 的 `ob_size`、`ob_item` 和元素字段。理由是：

1. `poll/ppoll` 有两类返回结果：寄存器中的 ready count 和用户缓冲区中的逐 fd `revents`。`x0=1` 正确不代表后者正确。
2. 包装层会扫描整个 pollfd 数组，根据 `revents` 决定是否创建结果 tuple、创建几个 tuple、以什么顺序放入 list；任一事件位陈旧都能在进入 `GET_ITER` 前改变分配序列。
3. AArch64 上 `revents` 是 16 位字段，消费者很可能是 `ldrh/ldrsh`。当前普通值回放 MVP 只接受 `ldr w/x`，所以即使 46 个 allocator 站点全对，这个上游站点仍完全在覆盖范围外。

第二候选才是解释器并发状态，例如 `eval_breaker`、pending-call/signal 位或 GIL 交接后读取的线程/解释器状态。它们也可能使 poll 返回后多执行或少执行一段工作，但在排除 pollfd 输出之前不应先扩展到解释器全局状态。

### 1.3 用已有记录做四级语义比对

不需要逐指令单步，按下列层级找最早不一致点即可：

1. **syscall 输出层**：从 record 66 的 ENTRY 寄存器取得 `fds=x0`、`nfds=x1`（以实际 syscall ABI 为准），从 EXIT 差分重建 `[fds, fds + nfds*sizeof(struct pollfd))`，列出每项的 `fd/events/revents`。确认该记录在所选窗口中未被过滤，并确认 dirty/byte-run 的确覆盖 `revents` 两字节。
2. **syscall 续点层**：在切片 `rec.pc+4`（项目当前 aarch64 恢复语义）设一次性断点，读取同一 pollfd 数组。这里同时验证寄存器返回和内存副作用，能把问题分成“回放应用错”与“返回后消费错”。
3. **包装层结果层**：在 CPython poll 包装函数返回或 `PyObject_GetIter` 入口设断点，记录结果对象的 type、`ob_size`、元素地址及首元素内容。无需跟踪中间每条指令。
4. **分配流层**：在 `_PyObject_GC_Malloc/PyObject_Malloc` 入口记录前 16～32 个 `{ordinal, LR, size, type-or-caller}`，录制侧可由临时轻量探针补齐，切片侧可由断点命令自动输出。比较第一处插入/删除/替换，而不是只看某个 allocator 站点的首事件。

如果第 1、2 层一致而第 3 层不同，就静态反汇编 pollfd 扫描循环，优先给读取 `revents`、结果 list 长度和元素指针的少数 load 加探针。若第 3 层仍一致而第 4 层不同，再转查 `eval_breaker`/pending work 和字节码调度状态。这样每轮都沿数据流缩小范围，不需执行级单步。

还可把已有边界差分作为候选过滤器：只保留有效地址落在“record 66 输出 byte-run”或“基座后首个边界前由其他线程改写的 byte-run”上的 load。页级相交只作粗筛，最终应落实到具体 byte range，避免把同页无关对象全列为候选。

## 2. 候选站点选择的投入产出

工程上的优先级建议是：**分歧探针差分 > 手工反向枚举 > census 作为补充普查**。

### 分歧探针差分：最高长期投入产出

它直接回答“哪个读使可观察状态首次不同”，结果可复现、可自动回归，也适用于推进到 653K 后的下一次深层分歧。建议把差分单位设为语义签名，而不只是 rc：

- poll 返回后：pollfd 内容和结果容器摘要；
- 分配入口：caller/type/size 序列；
- 候选 load：`{site, ordinal, effective_addr, value}`；
- 首个 allocator miss：expected run 与 actual address。

候选集可二分或按模块分组启用，找到能把最早分配流重新对齐的最小组。比“跳过某站点后看最终 rc”更灵敏，因为深层崩溃可能掩盖早期改善。

### 手工枚举：本轮最快的播种手段

当前分歧离基座只有几十条目标指令，沿 `poll return → wrapper result → GET_ITER → GC_New` 反向列出约 10～30 个 load，可能最快得到第一个答案。尤其应补 `ldrh/ldrsh`、`ldrb/ldrsb` 等窄 load 的识别和记录能力。但手工表随 Python/libc 版本漂移，不能继续作为 653K 后多轮分歧的主流程。

### census：修复便宜，但诊断分辨率不够

`PTRACE_PEEKDATA` 返回的合法数据若位 63 为 1，C 的 `long` 会是负数；错误判断必须是调用前 `errno=0`，调用后仅在 `r == -1 && errno != 0` 时认定失败。最好把返回值和成功状态分离，避免合法的全 1 数据仍含糊。

这个修复值得立即做，但当前 census 每页只记录第一个 fault，得到的是“某页被碰过”，不是“哪个 load 导致尺寸分歧”；同一页上的回放写、目标写和多个目标读还会互相遮蔽。它适合生成候选页或验证读集覆盖，不适合作为本轮唯一的因果定位器。若继续使用，应在无值回放跳板切片上跑，或明确识别全部 blob/trampoline PC 范围，并至少把 fault 解码成 read/write 与访问宽度。

## 3. 普通 load 首段序号语义

### 3.1 当前 `ord-from_ord` 在严格不变量下没有 off-by-one

设检查点已完成该站点 `F=from_ord` 次访问，切片从检查点后的下一条目标指令恢复，则窗口内第 `j` 次访问对应录制绝对序号 `F+j`。事件的正确运行段起点就是：

```text
start = event.ord - from_ord
```

因此普通 load 使用 `ord-from_ord` 是对的，`load_limit=to_ord-from_ord` 也与窗口访问数一致。合成段从 start=1 开始；若首个变化事件在相对序号 1，当前游标循环用 `next.start <= ordinal`，会从合成段推进到同为 start=1 的事件段，所以首读得到事件值；若首事件在 k>1，合成段覆盖 1..k-1。这里没有数学上的一阶偏移。

### 3.2 有两个隐藏的工程边界

第一，同一站点出现两个 `start=1` 段，正确性依赖“合成段先写、事件后写、游标对相等起点继续前进”三个实现细节。以后若排序、去重、压缩或并行生成 runs，语义可能静默反转。建议显式规范化：

- 若普通 load 的首事件相对序号为 1，不生成合成段；
- 若首事件相对序号大于 1，才生成 start=1 合成段；
- run 表强制验证 `start` 严格递增；
- 日志打印 `synth_end`、首事件相对序号和是否省略 synth。

第二，`from_ord` 坐标成立的前提是恢复点不会重执行一条在检查点 state 中已经计数的 load。当前 `atomic_trace_step_out()` 避免 checkpoint 留在记录跳板内部，这是必要条件；仍应加断言/测试覆盖“停在站点 branch 前、跳板内、返回后”三种时刻。若未来为了 syscall rewind、信号恢复或 probe 基座调整 PC，必须同时调整对应站点的起始 ordinal，不能只改 PC。

### 3.3 建议补的最小测试矩阵

对单个普通 load 站点构造 `from_ord=100`：

1. 首事件 ord=101，期望 replay ordinal 1 取事件值；
2. 首事件 ord=102，期望 ordinal 1 取 synth、ordinal 2 取事件值；
3. 多个连续变化事件 ord=101/102/103，逐次精确对应；
4. 窗口内无事件，站点不 patch 且真实值等价；
5. `to_ord==from_ord`，不生成站点且不因 load_limit 提前误退出；
6. 地址变化但值不变、值变化但地址不变，均产生正确新段；
7. 首读为 `ldrh/ldrsh` 的 pollfd.revents 场景，验证窄 load 零扩展/符号扩展语义。

原子站点现有 `+1` 是另一套经验语义，不应反向用于证明普通 load 也要 `+1`。更稳妥的做法是分别写出“checkpoint state 代表已完成多少次访问、恢复是否重执行一次”的不变量，再用上述微型测试固定；如果原子 `+1` 只能靠 SPSC 症状解释，建议另立测试审计其根因，而不要让两类站点共享含糊注释。

## 建议执行顺序

1. 立即核对 miss 站点的原始 `first_event.ord - from_ord`；这是当前结论是否成立的门槛。
2. 从 record 66 重建 pollfd 输出，验证 `revents` byte-run 与切片 `rec.pc+4` 内存完全一致。
3. 加三组语义探针：poll wrapper 出口、`PyObject_GetIter`、前 32 次 malloc；比较第一处序列差异。
4. 手工列出该最短路径的窄 load 与普通 load，作为分歧探针差分的首批候选。
5. 修 census 的 errno 判错，但只把它作为候选页生成器。
6. 将普通 load run 生成改为无重复 start 的规范形式，并补 7 项序号测试。

