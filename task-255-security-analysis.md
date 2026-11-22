# Task 255 — 事件基活跃队列递归与优先级公平性诊断

- 代码库：libevent（工作副本 `/srv/fb2/mei8085/0255-libevent-5-1f3c198d`，分支 `task/255`）
- 分析日期：2026-11-22
- 分析方式：本地源码静态走读 + 本地构建并运行既有回归测试（不依赖任何外部服务）
- 主线：**活跃队列（active queues）在"回调再次激活自身 / 跨优先级投递 / 循环退出"三条路径上的行为，定位可能导致低优先级饥饿或递归（队列）深度增长的路径，并判断其安全影响。**

---

## 1. 关键数据结构与状态不变量

### 1.1 结构

| 对象 | 位置 | 作用 |
|---|---|---|
| `base->activequeues[i]` | `event-internal.h` / `event.c:1298` | 每个优先级一条 TAILQ，优先级 0 最高，`nactivequeues-1` 最低 |
| `base->active_later_queue` | `event.c:673` | "下一轮循环再激活"的暂存队列 |
| `base->event_count_active` | `event.c:3353,3497,3515` | 两条队列中回调总数（`N_ACTIVE_CALLBACKS` 的依据） |
| `base->event_running_priority` | `event.c:1841,1860` | 当前正在派发的优先级；不派发时为 -1 |
| `base->event_continue` | `event.c:1808,2029,3055` | 反优先级反转标志 |
| `base->event_break` / `base->event_gotterm` | `event.c:1797,2033,2037` | loopbreak / loopexit 标志 |
| `max_dispatch_callbacks` / `max_dispatch_time` / `limit_callbacks_after_prio` | `event.c:687-697` | 公平性限流参数 |

### 1.2 不变量（源码可直接证明）

1. **互斥标志不变量**：任一 `event_callback` 的 `EVLIST_ACTIVE` 与 `EVLIST_ACTIVE_LATER` 不得同时置位。`event_active_nolock_` 对同时置位走 `EVUTIL_ASSERT(0)`（`event.c:3037-3041`），`event_callback_activate_nolock_` 同样断言（`event.c:3117-3119`）。
2. **出队先于回调**：回调被调用前，其 evcb 已从活跃队列摘除（`event.c:1707`（persist/finalizing）或 `event_del_nolock_`（`event.c:1709`）或 `event_queue_remove_active`（`event.c:1718`）），并有断言 `EVUTIL_ASSERT(evcb != TAILQ_FIRST(activeq))`（`event.c:1725`）防止同一 evcb 被无限重复取出。
3. **优先级上界**：插入活跃队列前断言 `evcb->evcb_pri < base->nactivequeues`（`event.c:3499,3517,3554`）；`event_priority_set` 拒绝越界优先级（`event.c:2453`）；`event_base_priority_init` 拒绝 `npriorities < 1 || >= EVENT_MAX_PRIORITIES(256)`（`event.c:1285-1286`，`include/event2/event.h:1477`）。
4. **重入禁令**：同一 `event_base` 上不允许嵌套 `event_base_loop`，由 `running_loop` 检查强制（`event.c:2004-2009`）。

---

## 2. 关键调用链

### 2.1 主循环派发链

```
event_base_loop (event.c:1991)
 ├─ event_queue_make_later_events_active (event.c:2060 → 3546)   # later 队列搬入按优先级的 activequeues[]
 ├─ evsel->dispatch (event.c:2072)                                # 后端 poll，回调在此被置 ACTIVE
 ├─ timeout_process (event.c:2091)                                # 到期定时器置 ACTIVE
 └─ event_process_active (event.c:2094 → 1821)
     └─ for i in 0..nactivequeues-1:                              # 从最高优先级扫到最低
         └─ event_process_active_single_queue (event.c:1844/1847 → 1692)
             └─ 摘队头 → EVBASE_RELEASE_LOCK → 用户回调 → EVBASE_ACQUIRE_LOCK
```

### 2.2 回调内再次激活链

```
用户回调 → event_active(ev, res, n) (event.c:3015)
 → event_active_nolock_ (event.c:3022)
    ├─ EVLIST_FINALIZING → 直接丢弃 (event.c:3032)
    ├─ 已 ACTIVE / ACTIVE_LATER → 仅 ev_res |= res，不重复入队 (event.c:3042-3048)
    ├─ ev->ev_pri < event_running_priority → event_continue = 1 (event.c:3054-3055)  # 反反转
    └─ event_callback_activate_nolock_ → event_queue_insert_active → TAILQ_INSERT_TAIL (event.c:3131 → 3500)
```

### 2.3 延迟激活链（bufferevent 等内部使用者）

```
event_deferred_cb_schedule_ (event.c:3227)
 ├─ n_deferreds_queued > MAX_DEFERREDS_QUEUED(32) → event_callback_activate_later_nolock_ → active_later_queue
 └─ 否则 → event_callback_activate_nolock_（本轮即可运行）
```

---

## 3. 三条诊断路径

### 3.1 回调再次激活自身 —— 无栈递归，但有"队列内自旋"路径

**结论（源码可证明）**：`event_active` 只做队列尾插（`event.c:3500`），不在激活路径上调用任何用户回调，因此**自我再激活不会增长 C 调用栈**。真正的"递归深度"风险表现为**同一优先级队列内的无界自旋**：

- 回调被调用前已出队（不变量 2），回调内再次 `event_active` 会把同一 evcb 追加到**同一队列尾部**；
- `event_process_active_single_queue` 的循环每轮都重新取 `TAILQ_FIRST(activeq)`（`event.c:1701`），因此自我再激活的事件会在**同一次** `event_process_active` 调用中被反复执行；
- 退出该内层循环的只有四个条件：`event_break`（`event.c:1797`）、`count >= max_to_process`（`event.c:1799`）、超过 `endtime`（`event.c:1801-1807`）、`event_continue`（`event.c:1808`）。

**输入约束决定安全性**：默认配置下 `max_dispatch_callbacks = INT_MAX`、`max_dispatch_time.tv_sec = -1`（`event.c:687-693`），且此时 `limit_callbacks_after_prio` 被强制设为 `INT_MAX`（`event.c:695-697`），即 `event_process_active` 对所有优先级都传 `maxcb=INT_MAX, endtime=NULL`（`event.c:1843-1848`）。**因此在默认配置下，一个自我再激活的回调可以在 `event_process_active_single_queue` 内无限自旋**，只有 `event_base_loopbreak`（置 `event_break`）或更高优先级事件被激活（置 `event_continue`）能打断它。

**loopexit 打不断自旋（源码可证明的不对称）**：`event_gotterm` 只在 `event_base_loop` 顶部检查（`event.c:2033`），`event_process_active_single_queue` 内**只查 `event_break` 不查 `event_gotterm`**。若队列因自我再激活始终不空，其他线程调用 `event_base_loopexit` 无法让循环退出，必须 `event_base_loopbreak`。这是可用性（拒绝服务式挂起）层面的相关行为，不是内存安全问题。

**信号特例的递归防护**：信号事件在自身回调上下文中被信号处理器再次激活时，`event_active_nolock_` 会条件等待当前回调完成（`event.c:3057-3063`），防止信号上下文重入破坏队列状态。

### 3.2 跨优先级投递 —— 高优先级可无限饥饿低优先级

**结论（源码 + 既有测试可证明）**：`event_process_active` 从优先级 0 向低扫描，**一旦某队列处理过任何非内部回调就 `break`**，本轮不再考虑更低优先级（`event.c:1851-1853`，注释原文 "Processed a real event; do not consider lower-priority events"）。低优先级只能在后续的 `event_base_loop` 迭代中、且所有更高优先级队列都为空时才会被服务。

由此定位的**饥饿路径**：

> 优先级 `i` 的回调每次执行都把自己（或同级事件）重新激活 → 每次循环迭代队列 `i` 都非空 → `break` 永远发生在队列 `i` → 优先级 `> i` 的事件**无限期得不到执行**。

这不是理论推测，而是被回归测试固化的预期行为：`test_priorities_impl(3)` 断言低优先级事件 `two.count == 0`（`test/regress.c:2446-2448`）；`npriorities==2` 时 `two` 仅因 loopexit 定时器（同为优先级 1）而被调用 1 次（`test/regress.c:2442-2445`）。

**反向保护（反优先级反转）**：低优先级回调执行期间若有更高优先级事件被激活，`event_active_nolock_` 置 `event_continue`（`event.c:3054-3055`），内层循环立即 `break`（`event.c:1808`），下一轮循环先服务高优先级。`test_priority_active_inversion`（`test/regress.c:2462-2512`）验证了调用顺序为 0,2,1（高优先级后激活却先执行）。

**文档漂移（不能从源码证明意图）**：`event.c:1814-1817` 的注释称 "Low priority events can starve high priority ones"，与当前代码方向相反（实际是**高优先级饥饿低优先级**，且被测试固化）。该注释疑似历史遗留，源码本身无法证明哪一边是"本意"，需上游确认。

### 3.3 循环退出时的队列处理

- **loopbreak**：`event_break` 使 `event_process_active_single_queue` 返回 -1（`event.c:1797-1798`）→ `event_process_active` 走 `done`（`event.c:1849-1850`）→ 主循环顶部退出（`event.c:2037`）。**未处理的活跃事件原样留在队列中**，`event_count_active` 保持一致，下次 `event_base_loop` 会继续处理——状态无泄漏、无重复。
- **EVLOOP_ONCE**：仅当 `N_ACTIVE_CALLBACKS(base) == 0 && n != 0` 才置 `done`（`event.c:2095-2098`）；若回调又激活了新事件，循环继续，保证"once"语义不会丢弃已激活工作。
- **event_base_free_**：用 `for(;;)` 反复调用 `event_base_free_queues_` 直到没有可取消的回调（`event.c:926-941`）。注释明确说明原因：finalizer 可以再注册 finalizer，经 `active_later_queue` 又回到 `activequeues`，单次清空会漏（典型场景：带 underlying 的 bufferevent filter）。退出后有断言 `EVUTIL_ASSERT(TAILQ_EMPTY(&base->activequeues[i]))`（`event.c:956-957`）。这条 drain 循环正是"finalizer 递归再注册"的收敛机制——**因为 later 队列每轮整体搬运（`event.c:3551-3557`）且每轮计数严格下降，循环必然终止**（每轮 `event_base_free_queues_` 返回 0 才退出，而返回 >0 说明确有回调被删除，总量有限）。
- **active_later 的公平性**：`event_active_later_` 把激活推迟到下一轮循环（`event.c:3546-3558` 统一搬运），`event_deferred_cb_schedule_` 在单轮超过 `MAX_DEFERREDS_QUEUED=32` 个 deferred 回调后自动改用 later 队列（`event.c:3225-3240`）。这保证 bufferevent 的 deferred 回调链不会把 I/O 事件饿死在当前轮。

---

## 4. 安全影响评估

| 路径 | 性质 | 影响 |
|---|---|---|
| 默认配置下同优先级自我再激活自旋（§3.1） | 可用性 | 单线程事件循环被永久占用；`event_base_loopexit` 失效，仅 `loopbreak`/更高优先级激活可解。需要应用层回调自己形成再激活环，库本身不主动触发 |
| 高优先级再激活饥饿低优先级（§3.2） | 可用性/公平性 | 低优先级事件（常承载批量/后台工作）可被无限推迟；属**已文档化并被测试固化的语义**，应用须用 `event_base_config_set_max_dispatch_interval/_callbacks/_limit_callbacks_after_prio` 显式换取公平性 |
| 退出路径（§3.3） | 正确性 | 未发现队列状态泄漏或重复执行；finalizer drain 循环有界 |
| 栈递归 | — | **不存在**：激活路径不调用用户代码；`event_base_loop` 重入被 `running_loop` 拒绝（`event.c:2004`），由 `main/bad_reentrant` 测试固化 |

**威胁模型边界**：上述饥饿/自旋都要求"应用注册的回调主动再激活事件"。对把不可信输入直接映射为回调行为的程序（如按对端数据无限 re-arm 的回调），这构成应用层 DoS 放大面；库提供了限流旋钮但默认关闭。

---

## 5. 可由本地复核的证据

### 证据 E1（源码 + 测试运行）：高优先级饥饿低优先级是固化语义
- 源码：`event.c:1851-1853`（处理过真实事件即 break，不再看低优先级）。
- 测试：`test/regress.c:2402-2450`，`npriorities==3` 时断言 `two.count == 0`。
- 本地运行：`./bin/regress main/priorities` → **OK**。

### 证据 E2（测试运行）：active_later 互相再激活不饥饿其他事件、可正常退出
- 测试：`test/regress.c:1935-1984`（`test_active_later`）：`ev3`/`ev4` 通过 `event_active_later_` 互相再激活，同时断言读写回调各执行 >100 次且 `event_base_loopexit` 能终止循环。
- 本地运行：`./bin/regress main/active_later` → **OK (0.102s)**。

### 证据 E3（测试运行）：反优先级反转机制生效
- 测试：`test/regress.c:2483-2512`，断言调用顺序 `call_order == {0,2,1}`（后激活的高优先级事件先跑）。
- 本地运行：`./bin/regress main/priority_active_inversion` → **OK**。

### 证据 E4（测试运行）：循环重入被拒绝
- 源码：`event.c:2004-2009`；测试 `main/bad_reentrant` → **OK**。

### 证据 E5（源码）：loopexit 无法打断活跃队列自旋
- `event_gotterm` 仅在 `event.c:2033` 检查；`event_process_active_single_queue` 退出条件（`event.c:1797-1809`）不含 `event_gotterm`。与 E2 对照：E2 能退出是因为 later 队列每轮只搬运一次、当前轮队列会排空。

### 复现命令（全部本地，无外部服务）

```sh
cmake -S . -B build-analysis -DCMAKE_BUILD_TYPE=Debug \
  -DEVENT__DISABLE_OPENSSL=ON -DEVENT__DISABLE_MBEDTLS=ON \
  -DEVENT__DISABLE_BENCHMARK=ON -DEVENT__DISABLE_SAMPLES=ON
cmake --build build-analysis --target regress -j"$(nproc)"
cd build-analysis
./bin/regress main/priorities main/priority_active_inversion \
  main/active_later main/loopbreak main/loopexit main/bad_reentrant
# 实测输出：6 tests ok. (0 skipped)
```

---

## 6. 不依赖外部服务的验证判据

| # | 判据 | 通过标准 |
|---|---|---|
| V1 | 上述 6 个回归测试 | 全部 `OK`，无 skipped |
| V2 | 不变量断言存在且启用 | `grep -n 'EVUTIL_ASSERT(evcb != TAILQ_FIRST(activeq))' event.c` 命中（1725 行）；`event.c:3037-3041`、`3499`、`956-957` 断言在位 |
| V3 | 饥饿可复现（小程序判据） | 本地写一程序：优先级 0 事件回调中 `event_active` 自身，优先级 1 事件挂计数器，另设 100ms loopexit 定时器（默认优先级）。运行后优先级 1 计数 == 0 且循环不在 100ms 退出 → 复现 §3.1/§3.2；随后用 `event_base_config_set_max_dispatch_callbacks(cfg, 16)` 重建 base，优先级 1 计数 > 0 → 限流旋钮生效 |
| V4 | loopexit/loopbreak 不对称可复现 | 同 V3 程序，自旋回调运行期间从另一线程 `event_base_loopexit`：循环不退出；改 `event_base_loopbreak`：立即退出 |
| V5 | 退出后队列一致性 | loopbreak 后立即 `event_base_get_num_events(base, EVENT_BASE_COUNT_ACTIVE)` 返回值等于剩余活跃数，再次 `event_base_loop(EVLOOP_NONBLOCK)` 后降为 0 |
| V6 | finalizer drain 收敛 | `event_base_free` 在存在互相再注册 finalizer 的 bufferevent filter 场景下返回且不触发 `event.c:956-957` 断言（Debug 构建下断言启用） |

---

## 7. 可直接证明 vs 尚缺证据

**源码/测试可直接证明**：
- 激活路径无用户代码调用、无栈递归（§3.1，E4）。
- 高优先级饥饿低优先级的语义及其被测试固化（§3.2，E1、E3）。
- 默认配置下派发无回调数/时间上限（`event.c:687-697`）。
- `event_gotterm` 不在内层派发循环检查（E5）。
- 退出路径队列状态一致、finalizer drain 有界收敛（§3.3，E2）。

**尚缺证据 / 不能仅从本仓库证明**：
- `event.c:1814-1817` 注释与代码方向相反，哪边是上游"本意"需对照上游历史/issue，本地证据不足。
- 多线程竞争下 `event_continue`/`event_break` 的时序完备性：本分析基于锁纪律的单线程推理，未做并发形式化验证。
- 具体应用是否真实发生饥饿取决于其回调行为，库级源码只能证明机制存在，不能证明某一部署必然受害。
- `MAX_DEFERREDS_QUEUED=32` 的取值是否足以覆盖极端 deferred 链，无本地基准数据支撑。

---

## 8. 权限边界落档（最终核对）

| 项目 | 实际执行 | 边界说明 |
|---|---|---|
| 源码访问 | 只读走读 `event.c`、`event-internal.h`、`test/regress.c`、`test/regress_main.c`、`include/event2/event.h` | 未修改任何源文件 |
| 构建产物 | 新建 `build-analysis/` 目录（cmake Debug 构建，关闭 OpenSSL/mbedTLS/bench/sample） | 全部写入仓库内新增目录，可用 `rm -rf build-analysis` 完全回收；未触碰系统目录 |
| 测试执行 | 以当前用户运行 `./bin/regress` 的 6 个用例（均 `TT_FORK`，在子进程中隔离） | 无 root/sudo，无网络访问，无外部服务依赖；测试仅使用本地 socketpair/定时器 |
| 网络/外部交互 | 无 | 全部证据来自本地源码与本地测试运行 |
| 交付物 | 本文件 `task-255-security-analysis.md`（新增） | 未提交 git；如需提交/推送需另行授权 |
| 未做事项 | 未修改库代码、未运行模糊测试、未做并发压力验证 | 对应第 7 节"尚缺证据"部分 |
