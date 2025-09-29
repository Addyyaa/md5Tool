### 问题现象

- 点击“分页查询一次”后，随即点击输入框/按钮，应用必现闪退。
- 控制台多次出现 Windows fatal exception: 0x8001010d 和 Access Violation，偶发没有 Python Traceback。
- 栈顶多次落在 `_apply_filter_and_show` 以及 UI 刷新相关调用上。

### 根因分析

- 0x8001010d/Access Violation 表征“非 UI 线程触碰 UI”或 UI 调用栈被重入破坏。
- 多处存在潜在触发点：
  - 网络回调（`QNetworkReply.finished` 或自定义信号）可能在非 UI 线程触发，直接进入 UI 刷新。
  - 信号/槽链路引起的“渲染重入”（正则、大小写、筛选下拉、滚动等变更在刷新中再次触发刷新）。
  - `setPlainText` 触发滚动/文本变化信号，形成递归/竞争。
  - 窗口关闭或控件销毁后，延迟回调仍触碰失效对象。

### 核心修复方案

- 保证 UI 只在主线程更新
  - 将 `ApiClient` → `MainWindow` 的所有信号改为 `Qt.QueuedConnection`。
  - 网络路径中所有 UI 更新用 `QTimer.singleShot(0, ...)` 投递到事件循环。
  - `QNetworkReply.finished` 只断开当前槽（避免误断开其它连接），并经事件队列切换后再处理。

- 统一的延迟渲染通道
  - 新增 `_renderTimer`（singleShot），集中调度渲染。
  - `_apply_filter_and_show` 不再直接触碰 UI；仅计算结果并写入 `_pending_render`，触发 `_renderTimer.start(0)`。
  - 新增 `@Slot()` `_do_render`：在主线程下一拍读取 `_pending_render`，最小触碰（`blockSignals`、受控滚动）执行 `setPlainText`，最后清空 pending。

- 防重入与信号屏蔽
  - 用 `_in_render` 防止渲染重入；用 `_in_scroll_update` 防止滚动引发的级联信号。
  - `setPlainText` 前后 `blockSignals(True/False)`，并妥善恢复。
  - 恢复筛选器时 `blockSignals(True/False)`，避免初始化/恢复引发重入。

- 请求与回调的并发治理
  - 发起新分页请求前 `abort` 旧 `QNetworkReply`，消除回调交叉。
  - 一次性槽（`finished.disconnect(当前槽)`）避免重复进入同一回调。

- 对象生存期守护
  - 引入 `shiboken6.isValid` 的“对象有效性”检测，延迟渲染前校验 `MainWindow`/`logView` 有效；若无效，直接放弃渲染。
  - `closeEvent` 中停止 `_renderTimer`，避免窗口销毁后回调触碰 UI。

- 可观测性
  - 启用 `faulthandler` 到文件，便于捕获原生崩溃栈（进程级崩溃时普通日志可能来不及输出）。

### 关键改动一览（高层）

- 信号连接：全部 UI 槽使用 `@Slot(...)` 注解，信号使用 `Qt.QueuedConnection`。
- 网络回调：`logsFetched.emit` 和列表处理后续 UI 更新一律 `singleShot(0, ...)`。
- 渲染路径：`_apply_filter_and_show` → `_pending_render` → `_renderTimer` → `_do_render`，统一出入口。
- 重入控制：`_in_render`、`_in_scroll_update` 与 `blockSignals`。
- 资源治理：分页请求前 `abort` 上一个 reply；`finished` 断开当前槽；`closeEvent` 停止 `_renderTimer`。
- 有效性检查：使用 `shiboken6.isValid` 防止触碰失效对象。

### 经验与建议

- 只在主线程更新 UI：信号用 `Qt.QueuedConnection`，耗时计算放后台，UI 线程只做合并后的“单次更新”。
- 严格防重入：对可能触发连锁的 UI 刷新（文本、滚动、筛选）统一排队、单通道执行。
- 延迟执行优于即时执行：`QTimer.singleShot(0, ...)` 能有效避免栈交错与跨线程调用。
- 生命周期管理：定时器、回调在窗口关闭时必须停止/校验对象有效性。
- 诊断通道：保留 `faulthandler` 与简洁的调试日志，便于定位原生层异常。

这次修复将 UI 更新彻底“排队、串行、主线程化”，并确保对象有效性和回调一次性，从根因上解决了点击后即时交互导致的崩溃。后续如果日志量更大，建议把“文本拼接/过滤/排序”移至后台线程（如 `QRunnable/QThreadPool`），主线程只做一次性 `setPlainText`，进一步提升稳定性与流畅度。
