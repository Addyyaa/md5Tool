"""
PySide6 日志查看工具

功能要点（遵循用户规则与 UI 规范）：
- 管理员登录获取 Token（可手动粘贴 Token）
- 抓取日志接口：GET /api/v1/errorTraceLog/fetch/logs?deviceId=...&path=...
- 异步网络请求（QNetworkAccessManager），不阻塞 UI
- 自动刷新（可配置周期）、正则过滤、导出/清空
- 明暗主题切换、状态栏提示、QSettings 持久化
- 遵循 SRP/DRY/KISS，组件化与可复用设计
"""

from __future__ import annotations

# pylint: disable=no-name-in-module, import-error

import json
import re
from dataclasses import dataclass
import datetime as _dt
import time
from typing import Optional

from PySide6.QtCore import (
    QObject,
    QSettings,
    QTimer,
    QUrl,
    QUrlQuery,
    QByteArray,
    Signal,
    Qt,
)
from PySide6.QtGui import QAction, QIcon
from PySide6.QtNetwork import (
    QNetworkAccessManager,
    QNetworkRequest,
    QAuthenticator,
    QNetworkReply,
    QNetworkCookieJar,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QFileDialog,
    QToolButton,
    QSpinBox,
    QStatusBar,
    QWidget,
)


@dataclass
class LoginResult:
    """登录结果数据结构。"""

    success: bool
    token: str = ""
    error_message: str = ""


class ApiClient(QObject):
    """基于 QNetworkAccessManager 的 API 客户端。

    说明：
    - 使用异步请求与信号，不阻塞 UI；
    - host 与 token 由外部注入，符合依赖注入原则；
    - 登录端点可配置，便于适配不同服务。
    """

    loginFinished = Signal(LoginResult)
    logsFetched = Signal(str)
    requestFailed = Signal(str)
    debugMessage = Signal(str)
    recordsReceived = Signal(object)

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._host: str = ""
        self._token: str = ""
        self._manager = QNetworkAccessManager(self)
        self._ignore_ssl_errors: bool = False
        self._prefer_https_default: bool = False
        self.last_username: str = ""
        self.last_password: str = ""
        self._debug_enabled: bool = False
        self._req_meta: dict[int, dict] = {}
        # 使用 CookieJar 维持会话（部分接口将 token 写入 Set-Cookie）
        self._manager.setCookieJar(QNetworkCookieJar(self))
        # 处理 HTTP 基本认证（如网关 401）
        self._manager.authenticationRequired.connect(self._on_auth_required)

    def set_host(self, host: str) -> None:
        """规范化 Host：
        - 若无协议：按 prefer_https 默认补全 https:// 或 http://
        - 确保以单个斜杠结尾，便于后续拼接路径
        """
        if not host:
            self._host = ""
            return

        text = host.strip()
        # 若缺少协议，根据 prefer_https 选择默认协议
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text):
            text = ("https://" if self._prefer_https_default else "http://") + text

        # 统一结尾斜杠
        if not text.endswith("/"):
            text = text + "/"
        self._host = text

    def set_options(
        self,
        *,
        ignore_ssl_errors: bool,
        prefer_https_default: bool,
        debug_enabled: bool = False,
    ) -> None:
        self._ignore_ssl_errors = bool(ignore_ssl_errors)
        self._prefer_https_default = bool(prefer_https_default)
        self._debug_enabled = bool(debug_enabled)

    def _debug(self, message: str) -> None:
        if getattr(self, "_debug_enabled", False):
            self.debugMessage.emit(message)

    def _attach_handlers(self, reply) -> None:  # type: ignore[no-untyped-def]
        # 附加 SSL 错误处理
        # 对于部分构建，sslErrors 信号可能不存在；这里做保护
        if hasattr(reply, "sslErrors"):
            reply.sslErrors.connect(lambda _errs, r=reply: self._on_ssl_errors(r))  # type: ignore[attr-defined]

    def _on_ssl_errors(self, reply) -> None:  # type: ignore[no-untyped-def]
        if self._ignore_ssl_errors and hasattr(reply, "ignoreSslErrors"):
            reply.ignoreSslErrors()  # type: ignore[attr-defined]

    def _on_auth_required(self, _reply, authenticator: QAuthenticator) -> None:  # type: ignore[no-untyped-def]
        # 若服务器要求 Basic/Digest 认证，使用登录输入的用户名密码
        # 注意：这是与登录接口不同层的网关认证
        # 尽量不覆盖已有凭据
        if not authenticator.user():
            # 从最近一次尝试的用户名/密码获取
            username = self.last_username
            password = self.last_password
            if username:
                authenticator.setUser(username)
                authenticator.setPassword(password)

    def set_token(self, token: str) -> None:
        self._token = token or ""

    # --------------------- 登录与 Token 获取 ---------------------
    def login(
        self, login_path: str, username: str, password: str, mode: str = "POST_JSON"
    ) -> None:
        """管理员登录以获取 Token。

        假设：POST {host}/{login_path}，JSON: {"username":..., "password":...}
        返回：{ token: "..." } 或 { data: { token: "..." } }
        """
        if not self._host:
            self.requestFailed.emit("Host 不能为空")
            return

        path = login_path.lstrip("/")
        url = QUrl(self._host + path)

        request = QNetworkRequest(url)
        request.setRawHeader(b"Accept", b"application/json")

        if mode == "GET":
            q = QUrlQuery()
            q.addQueryItem("username", username)
            q.addQueryItem("password", password)
            url.setQuery(q)
            request.setUrl(url)
            reply = self._manager.get(request)
        elif mode == "POST_FORM":
            request.setHeader(
                QNetworkRequest.ContentTypeHeader,
                "application/x-www-form-urlencoded",
            )
            q = QUrlQuery()
            q.addQueryItem("username", username)
            q.addQueryItem("password", password)
            payload = q.toString(QUrl.FullyEncoded).encode("utf-8")
            reply = self._manager.post(request, QByteArray(payload))
        else:
            request.setHeader(QNetworkRequest.ContentTypeHeader, "application/json")
            payload = json.dumps({"username": username, "password": password}).encode(
                "utf-8"
            )
            reply = self._manager.post(request, QByteArray(payload))
        # 调试：请求预览
        if "payload" in locals() and isinstance(payload, (bytes, bytearray)):
            preview = payload[:512].decode("utf-8", errors="ignore")
        else:
            preview = ""
        self._debug(f"登录请求 {mode} -> {url.toString()}\nbody: {preview}")

        self._attach_handlers(reply)
        reply.finished.connect(lambda r=reply: self._handle_login_reply(r))

    def _handle_login_reply(self, reply: QNetworkReply) -> None:  # type: ignore[no-untyped-def]
        status = reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)
        reason = reply.attribute(QNetworkRequest.HttpReasonPhraseAttribute)
        data_text = bytes(reply.readAll()).decode("utf-8", errors="ignore")

        # 优先尝试解析 JSON 并提取 token（即便 Qt 标记为 Unknown error 但 HTTP=200 也尝试）
        obj = {}
        if data_text:
            try:
                obj = json.loads(data_text)
            except (json.JSONDecodeError, ValueError):
                obj = {}

        token = ""
        if isinstance(obj, dict):
            data_field = obj.get("data")
            token = (
                obj.get("token")
                or obj.get("access_token")
                or (data_field.get("token") if isinstance(data_field, dict) else None)
                or (data_field if isinstance(data_field, str) else None)
                or ""
            )
            # 兼容返回 {code:0,success:true,...} 但 data 为 null 的情况：
            # 此时可能把令牌下发在 Set-Cookie 中，或需要拼接 "Bearer " 前缀；
            # 如果上面未取到 token，尝试从常见 header 中回退（尽力而为）。
            if not token:
                auth_header = (
                    reply.rawHeader(b"Authorization")
                    .data()
                    .decode("utf-8", errors="ignore")
                    if reply.hasRawHeader(b"Authorization")
                    else ""
                )
                if auth_header.startswith("Bearer "):
                    token = auth_header[len("Bearer ") :]

        if token:
            self._token = token
            self.loginFinished.emit(LoginResult(True, token, ""))
            self._debug(
                f"登录响应 HTTP {status} {reason}，已解析到 token（长度 {len(token)}）"
            )
            reply.deleteLater()
            return

        # 若 Qt 标记错误且未解析出 token，则返回更详细错误
        if reply.error():
            extra = f" (HTTP {status} {reason})" if status else ""
            error_msg = reply.errorString() + extra
            self.loginFinished.emit(
                LoginResult(False, "", f"登录失败：{error_msg}\t{data_text}")
            )
            self._debug(f"登录失败 HTTP {status} {reason}：{data_text[:300]}")
            reply.deleteLater()
            return

        # 走到这里：没有 token 也没有 Qt 错误，但响应体不可用
        extra = f" (HTTP {status} {reason})" if status else ""
        snippet = ("；响应体：" + data_text[:300]) if data_text else ""
        self.loginFinished.emit(
            LoginResult(False, "", f"响应中未找到 token{extra}{snippet}")
        )
        self._debug(f"登录响应未含 token HTTP {status} {reason}：{data_text[:300]}")
        reply.deleteLater()

    # --------------------- 日志抓取 ---------------------
    def fetch_logs(self, device_id: str, log_path: str) -> None:
        """抓取日志文本。"""
        if not self._host:
            self.requestFailed.emit("Host 不能为空")
            return

        # 固定为题述接口路径；如需扩展，可外部传入或加入设置项。
        url = QUrl(self._host + "api/v1/errorTraceLog/fetch/logs")
        query = QUrlQuery()
        query.addQueryItem("deviceId", device_id)
        query.addQueryItem("path", log_path)
        url.setQuery(query)

        request = QNetworkRequest(url)
        request.setHeader(QNetworkRequest.ContentTypeHeader, "application/json")
        # 请求预览通过 debug 开关控制

        if self._token:
            request.setRawHeader(
                b"Authorization", f"Bearer {self._token}".encode("utf-8")
            )

        start_ts = time.time()
        reply = self._manager.get(request)
        request.setRawHeader(b"Accept", b"application/json")
        self._attach_handlers(reply)
        # 调试：抓取请求预览
        self._req_meta[id(reply)] = {
            "t0": start_ts,
            "method": "GET",
            "url": url.toString(),
            "query": query.toString(QUrl.FullyEncoded),
        }
        self._debug(
            f"抓取请求 GET -> {url.toString()}?{self._req_meta[id(reply)]['query']}"
        )
        reply.finished.connect(lambda r=reply: self._handle_logs_reply(r))

    def _handle_logs_reply(self, reply: QNetworkReply) -> None:  # type: ignore[no-untyped-def]
        status = reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)
        reason = reply.attribute(QNetworkRequest.HttpReasonPhraseAttribute)
        data_text = bytes(reply.readAll()).decode("utf-8", errors="ignore")

        # 即便 Qt 报 Unknown error，只要 HTTP 200/206 且拿到内容，优先展示日志
        if data_text and (not reply.error() or status in (200, 206)):
            self.logsFetched.emit(data_text)
            self._debug(f"抓取成功 HTTP {status} {reason}，长度 {len(data_text)}")
            # 输出调试指标
            meta = self._req_meta.pop(id(reply), None)
            if meta is not None:
                cost_ms = int((time.time() - meta["t0"]) * 1000)
                self.debugMessage.emit(
                    f"[抓取完成] {meta['method']} {meta['url']}?{meta['query']} | 用时 {cost_ms}ms | 状态 {status}"
                )
            reply.deleteLater()
            return

        extra = f" (HTTP {status} {reason})" if status else ""
        snippet = ("；响应体：" + data_text[:300]) if data_text else ""
        self.requestFailed.emit(f"抓取失败：{reply.errorString()}{extra}{snippet}")
        self._debug(f"抓取失败 HTTP {status} {reason}：{data_text[:300]}")
        # 输出调试指标
        meta = self._req_meta.pop(id(reply), None)
        if meta is not None:
            cost_ms = int((time.time() - meta["t0"]) * 1000)
            self.debugMessage.emit(
                f"[抓取失败] {meta['method']} {meta['url']}?{meta['query']} | 用时 {cost_ms}ms | 错误 {reply.errorString()}"
            )
        reply.deleteLater()

    def list_error_logs(self, page_size: int, page_num: int, creator: str) -> None:
        """分页查询服务器已上报的错误追踪日志。

        端点：POST /api/v1/manage/errorTraceLog/list/page
        负载：{"pageSize":10, "pageNum":1, "creator":"..."}
        """
        if not self._host:
            self.requestFailed.emit("Host 不能为空")
            return

        url = QUrl(self._host + "api/v1/manage/errorTraceLog/list/page")
        request = QNetworkRequest(url)
        request.setRawHeader(b"Accept", b"application/json")
        request.setHeader(QNetworkRequest.ContentTypeHeader, "application/json")

        if self._token:
            request.setRawHeader(
                b"Authorization", f"Bearer {self._token}".encode("utf-8")
            )

        payload_obj = {
            "pageSize": int(page_size),
            "pageNum": int(page_num),
            "creator": creator or "",
        }
        payload = json.dumps(payload_obj, ensure_ascii=False).encode("utf-8")
        self._debug(
            f"分页查询 POST -> {url.toString()}\nbody: {payload[:512].decode('utf-8', errors='ignore')}"
        )

        start_ts = time.time()
        reply = self._manager.post(request, QByteArray(payload))
        self._attach_handlers(reply)
        self._req_meta[id(reply)] = {
            "t0": start_ts,
            "method": "POST",
            "url": url.toString(),
            "bodyPreview": payload[:512].decode("utf-8", errors="ignore"),
        }
        self._debug(
            f"分页查询 POST -> {url.toString()} | body: {self._req_meta[id(reply)]['bodyPreview']}"
        )
        reply.finished.connect(lambda r=reply: self._handle_list_reply(r))

    def _handle_list_reply(self, reply: QNetworkReply) -> None:  # type: ignore[no-untyped-def]
        status = reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)
        reason = reply.attribute(QNetworkRequest.HttpReasonPhraseAttribute)
        data_text = bytes(reply.readAll()).decode("utf-8", errors="ignore")

        # 尝试解析；若 data 为分页结构，提取列表字段合成为展示字符串
        pretty = data_text
        if data_text:
            try:
                obj = json.loads(data_text)
                # 常见分页结构：{data:{records:[...]}} 或 {data:[...]} 或 {records:[...]}
                records = None
                if isinstance(obj, dict):
                    data_field = obj.get("data")
                    if isinstance(data_field, dict) and "records" in data_field:
                        records = data_field.get("records")
                    elif isinstance(data_field, list):
                        records = data_field
                    elif "records" in obj and isinstance(obj["records"], list):
                        records = obj["records"]
                # 兼容 data 直接是字符串日志（如 cmd）
                if isinstance(records, list):
                    pretty = json.dumps(records, ensure_ascii=False, indent=2)
                else:
                    # 若 obj 本身就是字符串，直接展示
                    if isinstance(obj, str):
                        pretty = obj
                    else:
                        pretty = json.dumps(obj, ensure_ascii=False, indent=2)
            except (json.JSONDecodeError, ValueError):
                pretty = data_text

        if (pretty is not None) and (not reply.error() or status in (200, 206)):
            # 若解析到 records 列表，向 UI 发送结构化数据用于 method/module 过滤
            try:
                obj = json.loads(data_text)
                records = None
                if isinstance(obj, dict):
                    data_field = obj.get("data")
                    if isinstance(data_field, dict) and isinstance(
                        data_field.get("records"), list
                    ):
                        records = data_field.get("records")
                    elif isinstance(data_field, list):
                        records = data_field
                    elif isinstance(obj.get("records"), list):
                        records = obj.get("records")
                if isinstance(records, list):
                    self.recordsReceived.emit(records)
            except (json.JSONDecodeError, ValueError, TypeError):  # 安全兜底，保持展示
                pass
            self.logsFetched.emit(pretty or "")
            # 输出调试指标
            meta = self._req_meta.pop(id(reply), None)
            if meta is not None:
                cost_ms = int((time.time() - meta["t0"]) * 1000)
                self.debugMessage.emit(
                    f"[分页完成] {meta['method']} {meta['url']} | 用时 {cost_ms}ms | 状态 {status}"
                )
            self._debug(f"分页查询成功 HTTP {status} {reason}，长度 {len(pretty)}")
            reply.deleteLater()
            return

        extra = f" (HTTP {status} {reason})" if status else ""
        snippet = ("；响应体：" + data_text[:300]) if data_text else ""
        self.requestFailed.emit(f"分页查询失败：{reply.errorString()}{extra}{snippet}")
        self._debug(f"分页查询失败 HTTP {status} {reason}：{data_text[:300]}")
        # 输出调试指标
        meta = self._req_meta.pop(id(reply), None)
        if meta is not None:
            cost_ms = int((time.time() - meta["t0"]) * 1000)
            self.debugMessage.emit(
                f"[分页失败] {meta['method']} {meta['url']} | 用时 {cost_ms}ms | 错误 {reply.errorString()}"
            )
        reply.deleteLater()


class MainWindow(QMainWindow):
    """日志查看器主窗口。"""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("202Logger - 日志查看器")
        self.setWindowIcon(QIcon("asserts/md5.ico"))

        # 状态栏
        self._status = QStatusBar()
        self.setStatusBar(self._status)

        # API 客户端
        self._api = ApiClient(self)
        self._api.loginFinished.connect(self._on_login_finished)
        self._api.logsFetched.connect(self._on_logs_fetched)
        self._api.requestFailed.connect(self._on_request_failed)
        self._api.debugMessage.connect(self._on_debug_message)
        self._api.recordsReceived.connect(self._on_records_received)

        # 自动刷新定时器
        self._timer = QTimer(self)
        self._timer.setInterval(5000)
        self._timer.timeout.connect(self._on_timer_tick)
        self._is_fetching: bool = False
        self._last_shown_hash: int = 0
        self._last_compiled_pattern: str = ""
        self._last_compiled_flags: int = 0
        self._compiled_regex = None
        # 懒加载窗口化：仅渲染一部分行，滚动顶部再加载更多
        self._lines_all: list[str] = []
        self._window_start: int = 0
        self._window_end: int = 0
        self._chunk_lines: int = 2000
        self._in_scroll_update: bool = False
        self._last_records_for_filters: list[dict] = []
        # 请求指标
        self._req_meta: dict[int, dict] = {}

        # 请求超时保护（避免用户感觉“没反应”）
        self._requestTimer = QTimer(self)
        self._requestTimer.setSingleShot(True)
        self._requestTimer.setInterval(30000)  # 30s 超时
        self._requestTimer.timeout.connect(self._on_request_timeout)

        # UI 组件
        central = QWidget(self)
        layout = QGridLayout(central)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setHorizontalSpacing(10)
        layout.setVerticalSpacing(10)

        # 分组：服务与登录
        grp_conn = QGroupBox("服务与登录", self)
        grid_conn = QGridLayout(grp_conn)

        self.hostEdit = QLineEdit()
        self.hostEdit.setPlaceholderText("示例：https://example.com/")
        grid_conn.addWidget(QLabel("Host"), 0, 0)
        grid_conn.addWidget(self.hostEdit, 0, 1)

        self.loginPathEdit = QLineEdit()
        self.loginPathEdit.setPlaceholderText("示例：/api/v1/auth/login")
        grid_conn.addWidget(QLabel("登录路径"), 1, 0)
        grid_conn.addWidget(self.loginPathEdit, 1, 1)

        self.preferHttpsCheck = QCheckBox("默认使用 HTTPS")
        self.ignoreSslCheck = QCheckBox("忽略证书错误(开发环境)")
        self.loginModeCombo = QComboBox()
        self.loginModeCombo.addItems(["POST_JSON", "POST_FORM", "GET"])
        self.loginModeCombo.setCurrentIndex(0)
        row_proto = QHBoxLayout()
        row_proto.addWidget(self.preferHttpsCheck)
        row_proto.addWidget(self.ignoreSslCheck)
        row_proto.addWidget(QLabel("登录方式"))
        row_proto.addWidget(self.loginModeCombo)
        grid_conn.addLayout(row_proto, 1, 2)

        self.usernameEdit = QLineEdit()
        self.usernameEdit.setPlaceholderText("管理员账号")
        grid_conn.addWidget(QLabel("用户名"), 2, 0)
        grid_conn.addWidget(self.usernameEdit, 2, 1)

        self.passwordEdit = QLineEdit()
        self.passwordEdit.setEchoMode(QLineEdit.Password)
        self.passwordEdit.setPlaceholderText("管理员密码")
        grid_conn.addWidget(QLabel("密码"), 3, 0)
        grid_conn.addWidget(self.passwordEdit, 3, 1)

        btn_login = QPushButton("登录获取 Token")
        btn_login.clicked.connect(self._on_click_login)
        grid_conn.addWidget(btn_login, 4, 1)

        self.tokenEdit = QLineEdit()
        self.tokenEdit.setPlaceholderText("可手动粘贴 Token（优先使用）")
        grid_conn.addWidget(QLabel("Token"), 5, 0)
        grid_conn.addWidget(self.tokenEdit, 5, 1)

        # 分组：日志抓取
        grp_fetch = QGroupBox("日志抓取", self)
        grid_fetch = QGridLayout(grp_fetch)

        self.deviceEdit = QLineEdit()
        self.deviceEdit.setPlaceholderText("示例：PS91d7ecLtest30")
        grid_fetch.addWidget(QLabel("deviceId"), 0, 0)
        grid_fetch.addWidget(self.deviceEdit, 0, 1)

        self.pathEdit = QLineEdit()
        self.pathEdit.setPlaceholderText("示例：/customer/logs/pintura/pintura.log")
        grid_fetch.addWidget(QLabel("日志路径"), 1, 0)
        grid_fetch.addWidget(self.pathEdit, 1, 1)

        btn_fetch = QPushButton("抓取一次")
        btn_fetch.clicked.connect(self._on_click_fetch)
        grid_fetch.addWidget(btn_fetch, 2, 1)

        # 分组：服务器分页查询
        grp_query = QGroupBox("服务器分页查询", self)
        grid_query = QGridLayout(grp_query)

        self.pageSizeEdit = QSpinBox()
        self.pageSizeEdit.setRange(1, 1000)
        self.pageSizeEdit.setValue(10)
        self.pageNumEdit = QSpinBox()
        self.pageNumEdit.setRange(1, 100000)
        self.pageNumEdit.setValue(1)
        self.creatorEdit = QLineEdit()
        self.creatorEdit.setPlaceholderText("示例：PSe5f3ffL006895")

        grid_query.addWidget(QLabel("pageSize"), 0, 0)
        grid_query.addWidget(self.pageSizeEdit, 0, 1)
        grid_query.addWidget(QLabel("pageNum"), 0, 2)
        grid_query.addWidget(self.pageNumEdit, 0, 3)
        grid_query.addWidget(QLabel("creator"), 1, 0)
        grid_query.addWidget(self.creatorEdit, 1, 1, 1, 3)

        btn_query = QPushButton("分页查询一次")
        btn_query.clicked.connect(self._on_click_query)
        grid_query.addWidget(btn_query, 2, 3)

        # 分组：刷新与过滤
        grp_tools = QGroupBox("刷新与过滤", self)
        grid_tools = QGridLayout(grp_tools)

        self.refreshSpin = QSpinBox()
        self.refreshSpin.setRange(1, 3600)
        self.refreshSpin.setValue(5)
        grid_tools.addWidget(QLabel("自动刷新(秒)"), 0, 0)
        grid_tools.addWidget(self.refreshSpin, 0, 1)

        self.refreshSourceCombo = QComboBox()
        self.refreshSourceCombo.addItems(["抓取设备日志(fetch)", "服务器分页(list)"])
        grid_tools.addWidget(QLabel("自动刷新来源"), 0, 2)
        grid_tools.addWidget(self.refreshSourceCombo, 0, 3)

        btn_start = QPushButton("开始自动刷新")
        btn_stop = QPushButton("停止自动刷新")
        btn_start.clicked.connect(self._on_click_start_auto)
        btn_stop.clicked.connect(self._on_click_stop_auto)
        row0 = QHBoxLayout()
        row0.addWidget(btn_start)
        row0.addWidget(btn_stop)
        grid_tools.addLayout(row0, 0, 2)

        self.regexEdit = QLineEdit()
        self.regexEdit.setPlaceholderText("输入正则以过滤显示（留空显示全部）")
        grid_tools.addWidget(QLabel("过滤正则"), 1, 0)
        grid_tools.addWidget(self.regexEdit, 1, 1)

        self.caseCheck = QCheckBox("不区分大小写")
        self.caseCheck.setChecked(True)
        grid_tools.addWidget(self.caseCheck, 1, 2)
        # 正则与大小写变化时，实时应用
        self.regexEdit.textChanged.connect(self._apply_filter_and_show)
        self.caseCheck.toggled.connect(lambda _v: self._apply_filter_and_show())

        self.maxLinesSpin = QSpinBox()
        self.maxLinesSpin.setRange(200, 200000)
        self.maxLinesSpin.setValue(5000)
        grid_tools.addWidget(QLabel("最大显示行数"), 1, 3)
        grid_tools.addWidget(self.maxLinesSpin, 1, 4)
        self.maxLinesSpin.valueChanged.connect(lambda _v: self._apply_filter_and_show())

        # 新增：外部 method 过滤 与 内部模块过滤
        self.methodCombo = QComboBox()
        self.methodCombo.setEditable(False)
        self.methodCombo.addItem("(全部方法)", "")
        self.moduleCombo = QComboBox()
        self.moduleCombo.setEditable(False)
        self.moduleCombo.addItem("(全部模块)", "")
        grid_tools.addWidget(QLabel("method"), 2, 0)
        grid_tools.addWidget(self.methodCombo, 2, 1)
        grid_tools.addWidget(QLabel("module"), 2, 2)
        grid_tools.addWidget(self.moduleCombo, 2, 3)
        # 创建时间筛选（下拉，自动聚合）
        self.createTimeCombo = QComboBox()
        self.createTimeCombo.setEditable(False)
        grid_tools.addWidget(QLabel("createTime"), 3, 0)
        grid_tools.addWidget(self.createTimeCombo, 3, 1, 1, 3)

        btn_apply_filters = QPushButton("应用筛选")
        btn_apply_filters.clicked.connect(self._apply_filter_and_show)
        grid_tools.addWidget(btn_apply_filters, 2, 4)
        self.methodCombo.currentIndexChanged.connect(
            lambda _i: (self._save_filters(), self._apply_filter_and_show())
        )
        self.moduleCombo.currentIndexChanged.connect(
            lambda _i: (self._save_filters(), self._apply_filter_and_show())
        )
        self.createTimeCombo.currentIndexChanged.connect(
            lambda _i: (self._save_filters(), self._apply_filter_and_show())
        )

        # 分组：操作
        grp_actions = QGroupBox("操作", self)
        grid_actions = QGridLayout(grp_actions)

        btn_export = QPushButton("导出为文件…")
        btn_clear = QPushButton("清空显示")
        btn_export.clicked.connect(self._on_click_export)
        btn_clear.clicked.connect(self._on_click_clear)
        grid_actions.addWidget(btn_export, 0, 0)
        grid_actions.addWidget(btn_clear, 0, 1)

        # 日志显示与展开控制
        expand_bar = QHBoxLayout()
        self.expandBtn = QToolButton(self)
        self.expandBtn.setText("展开日志")
        self.expandBtn.setCheckable(True)
        self.expandBtn.setToolTip("展开后仅显示日志区域，再次点击还原")
        self.expandBtn.clicked.connect(self._on_toggle_expand)
        expand_bar.addWidget(self.expandBtn)
        expand_bar.addStretch(1)

        self.logView = QPlainTextEdit()
        self.logView.setReadOnly(True)
        self.logView.setLineWrapMode(QPlainTextEdit.NoWrap)
        # 性能优化：禁用撤销/最大块数限制
        self.logView.setUndoRedoEnabled(False)
        self.logView.document().setMaximumBlockCount(0)  # 我们用自定义最大行控制
        # 监听滚动，触顶懒加载更多
        self.logView.verticalScrollBar().valueChanged.connect(self._on_log_scroll)

        # 工具栏：主题
        theme_action = QAction("切换主题", self)
        theme_action.triggered.connect(self._toggle_theme)
        self.addAction(theme_action)
        self.menuBar().addAction(theme_action)

        # 调试开关
        self.debugCheck = QCheckBox("启用调试提示")
        self.statusBar().addPermanentWidget(self.debugCheck)

        # 布局（使用 Grid，遵循分组与对齐原则）
        layout.addWidget(grp_conn, 0, 0, 1, 2)
        layout.addWidget(grp_fetch, 1, 0, 1, 2)
        layout.addWidget(grp_query, 2, 0, 1, 2)
        layout.addWidget(grp_tools, 3, 0, 1, 2)
        layout.addWidget(grp_actions, 4, 0, 1, 2)
        layout.addLayout(expand_bar, 5, 0, 1, 2)
        layout.addWidget(self.logView, 6, 0, 1, 2)
        self._groups_for_expand = [
            grp_conn,
            grp_fetch,
            grp_query,
            grp_tools,
            grp_actions,
        ]
        self.setCentralWidget(central)

        # 载入设置
        self._settings = QSettings("202Studio", "202Logger")
        self._load_settings()

    # --------------------- 设置与主题 ---------------------
    def _apply_theme(self, dark: bool) -> None:
        if dark:
            self.setStyleSheet(
                """
                QWidget { color: #eaeaea; background-color: #202124; }
                QLineEdit, QPlainTextEdit, QGroupBox { background-color: #2b2c2f; border: 1px solid #3c4043; }
                QPushButton { background-color: #3c4043; border: 1px solid #5f6368; padding: 6px 12px; }
                QPushButton:hover { background-color: #4a4f55; }
                QLabel { color: #eaeaea; }
                QMenuBar { background-color: #202124; color: #eaeaea; }
                QStatusBar { background-color: #202124; color: #eaeaea; }
                """
            )
        else:
            self.setStyleSheet("")

    def _toggle_theme(self) -> None:
        dark = not self._settings.value("ui/dark", False, bool)
        self._settings.setValue("ui/dark", dark)
        self._apply_theme(dark)

    def _load_settings(self) -> None:
        self.hostEdit.setText(self._settings.value("conn/host", "", str))
        self.loginPathEdit.setText(
            self._settings.value("conn/loginPath", "/api/v1/auth/login", str)
        )
        self.usernameEdit.setText(self._settings.value("conn/username", "", str))
        # 密码不持久化，避免安全问题
        self.tokenEdit.setText(self._settings.value("conn/token", "", str))
        self.deviceEdit.setText(
            self._settings.value("fetch/deviceId", "PS91d7ecLtest30", str)
        )
        self.pathEdit.setText(
            self._settings.value(
                "fetch/path", "/customer/logs/pintura/pintura.log", str
            )
        )
        self.refreshSpin.setValue(self._settings.value("fetch/interval", 5, int))
        dark = self._settings.value("ui/dark", False, bool)
        self._apply_theme(dark)
        self.preferHttpsCheck.setChecked(
            self._settings.value("conn/preferHttps", False, bool)
        )
        self.ignoreSslCheck.setChecked(
            self._settings.value("conn/ignoreSsl", False, bool)
        )
        # 登录方式
        self.loginModeCombo.setCurrentText(
            self._settings.value("conn/loginMode", "POST_JSON", str)
        )
        self.debugCheck.setChecked(self._settings.value("dev/debug", False, bool))
        # 分页与来源
        self.pageSizeEdit.setValue(self._settings.value("list/pageSize", 10, int))
        self.pageNumEdit.setValue(self._settings.value("list/pageNum", 1, int))
        self.creatorEdit.setText(
            self._settings.value("list/creator", "PSe5f3ffL006895", str)
        )
        self.refreshSourceCombo.setCurrentText(
            self._settings.value("fetch/source", "抓取设备日志(fetch)", str)
        )
        self.maxLinesSpin.setValue(self._settings.value("view/maxLines", 5000, int))
        # 过滤器
        self._last_records_for_filters = []
        self._restore_filters()
        # 恢复时间筛选（下拉）
        sel_ct = self._settings.value("filter/createTime", "", str)
        if sel_ct:
            idx_ct = self.createTimeCombo.findData(sel_ct)
            if idx_ct >= 0:
                self.createTimeCombo.setCurrentIndex(idx_ct)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._settings.setValue("conn/host", self.hostEdit.text())
        self._settings.setValue("conn/loginPath", self.loginPathEdit.text())
        self._settings.setValue("conn/username", self.usernameEdit.text())
        self._settings.setValue("conn/token", self.tokenEdit.text())
        self._settings.setValue("fetch/deviceId", self.deviceEdit.text())
        self._settings.setValue("fetch/path", self.pathEdit.text())
        self._settings.setValue("fetch/interval", self.refreshSpin.value())
        self._settings.setValue("conn/preferHttps", self.preferHttpsCheck.isChecked())
        self._settings.setValue("conn/ignoreSsl", self.ignoreSslCheck.isChecked())
        self._settings.setValue("conn/loginMode", self.loginModeCombo.currentText())
        self._settings.setValue("dev/debug", self.debugCheck.isChecked())
        # 分页与来源
        self._settings.setValue("list/pageSize", self.pageSizeEdit.value())
        self._settings.setValue("list/pageNum", self.pageNumEdit.value())
        self._settings.setValue("list/creator", self.creatorEdit.text())
        self._settings.setValue("fetch/source", self.refreshSourceCombo.currentText())
        self._settings.setValue("view/maxLines", self.maxLinesSpin.value())
        self._save_filters()
        # 保存时间筛选
        self._settings.setValue(
            "filter/createTime", self.createTimeCombo.currentData() or ""
        )
        super().closeEvent(event)

    # --------------------- 事件处理 ---------------------
    def _on_click_login(self) -> None:
        host = self.hostEdit.text().strip()
        login_path = self.loginPathEdit.text().strip() or "/api/v1/auth/login"
        username = self.usernameEdit.text().strip()
        password = self.passwordEdit.text()

        if not host or not username or not password:
            self._warn("请填写 Host、用户名与密码。")
            return

        # 记录用于可能的 HTTP 基本认证
        self._api.last_username = username
        self._api.last_password = password
        self._api.set_options(
            ignore_ssl_errors=self.ignoreSslCheck.isChecked(),
            prefer_https_default=self.preferHttpsCheck.isChecked(),
            debug_enabled=self.debugCheck.isChecked(),
        )
        self._api.set_host(host)
        self._status.showMessage("正在登录…", 3000)
        mode = self.loginModeCombo.currentText()
        self._api.login(login_path, username, password, mode)

    def _on_login_finished(self, result: LoginResult) -> None:
        if result.success:
            self.tokenEdit.setText(result.token)
            self._api.set_token(result.token)
            self._ok("登录成功，已获取 Token。")
        else:
            self._error(f"登录失败：{result.error_message}")

    def _on_click_fetch(self) -> None:
        if self._is_fetching:
            self._status.showMessage("已有请求进行中，请稍候…", 3000)
            return
        host = self.hostEdit.text().strip()
        device_id = self.deviceEdit.text().strip()
        log_path = self.pathEdit.text().strip()

        if not host or not device_id or not log_path:
            self._warn("请填写 Host、deviceId 与 日志路径。")
            return

        # Token 优先来源：手动输入 > 登录获取
        token = self.tokenEdit.text().strip()
        self._api.set_options(
            ignore_ssl_errors=self.ignoreSslCheck.isChecked(),
            prefer_https_default=self.preferHttpsCheck.isChecked(),
            debug_enabled=self.debugCheck.isChecked(),
        )
        self._api.set_host(host)
        self._api.set_token(token)
        # 状态提示保持到数据展示/错误出现后再自动被覆盖
        self._status.showMessage("正在抓取日志…")
        self._is_fetching = True
        self._requestTimer.start()
        self._api.fetch_logs(device_id, log_path)

    def _on_click_query(self) -> None:
        if self._is_fetching:
            self._status.showMessage("已有请求进行中，请稍候…", 3000)
            return
        host = self.hostEdit.text().strip()
        if not host:
            self._warn("请填写 Host。")
            return

        token = self.tokenEdit.text().strip()
        self._api.set_options(
            ignore_ssl_errors=self.ignoreSslCheck.isChecked(),
            prefer_https_default=self.preferHttpsCheck.isChecked(),
            debug_enabled=self.debugCheck.isChecked(),
        )
        self._api.set_host(host)
        self._api.set_token(token)
        page_size = int(self.pageSizeEdit.value())
        page_num = int(self.pageNumEdit.value())
        creator = self.creatorEdit.text().strip()
        # 状态提示保持到数据展示/错误出现后再自动被覆盖
        self._status.showMessage("正在进行分页查询…")
        self._is_fetching = True
        # 清空旧窗口，避免残留
        self._lines_all = []
        self._window_start = 0
        self._window_end = 0
        self.logView.clear()
        self._requestTimer.start()
        self._api.list_error_logs(page_size, page_num, creator)

    def _on_logs_fetched(self, text: str) -> None:
        self._status.showMessage("日志抓取成功", 2000)
        self._raw_text = text or ""  # 原始文本用于过滤
        try:
            self._apply_filter_and_show()
        finally:
            self._is_fetching = False
            if self._requestTimer.isActive():
                self._requestTimer.stop()

    def _on_request_failed(self, message: str) -> None:
        try:
            self._error(message)
        finally:
            self._is_fetching = False
            if self._requestTimer.isActive():
                self._requestTimer.stop()

    def _on_request_timeout(self) -> None:
        # 超时兜底：复位状态并给出提示
        self._is_fetching = False
        self._status.showMessage("请求超时，请重试或检查网络。", 5000)

    # ------ 接收结构化 records，填充 method/module 过滤项 ------
    def _on_records_received(self, records: object) -> None:
        if not isinstance(records, list):
            return
        self._last_records_for_filters = records
        methods = set()
        modules = set()
        times = []
        for item in records:
            if isinstance(item, dict):
                m = item.get("method")
                if isinstance(m, str) and m:
                    methods.add(m)
                ct = item.get("createTime")
                if isinstance(ct, str) and ct:
                    times.append(ct)
                # errorMsg 可能是 JSON 字符串，内部键是模块名
                em = item.get("errorMsg")
                if isinstance(em, str) and em:
                    try:
                        em_obj = json.loads(em)
                        if isinstance(em_obj, dict):
                            for k in em_obj.keys():
                                if isinstance(k, str) and k:
                                    modules.add(k)
                    except (json.JSONDecodeError, ValueError, TypeError):
                        pass

        # 刷新下拉：保留“全部”项
        def refill(combo: QComboBox, values: set[str]) -> None:
            current = combo.currentData()
            combo.blockSignals(True)
            combo.clear()
            combo.addItem("(全部)", "")
            for v in sorted(values):
                combo.addItem(v, v)
            # 恢复之前所选（若仍存在）
            idx = combo.findData(current)
            combo.setCurrentIndex(idx if idx >= 0 else 0)
            combo.blockSignals(False)

        refill(self.methodCombo, methods)
        refill(self.moduleCombo, modules)
        # createTime 下拉：首项(全部)，其余按时间倒序，文本过长不自动换行
        current_ct = self.createTimeCombo.currentData()
        self.createTimeCombo.blockSignals(True)
        self.createTimeCombo.clear()
        self.createTimeCombo.addItem("(全部时间)", "")
        for t in sorted(set(times), reverse=True):
            # 本地时间显示，data 保留原始值
            local_str = self._to_local_display_time(t)
            display = local_str if len(local_str) <= 30 else (local_str[:27] + "…")
            self.createTimeCombo.addItem(display, t)
            self.createTimeCombo.setItemData(
                self.createTimeCombo.count() - 1, local_str, Qt.ToolTipRole
            )
        # 恢复之前所选
        idx = self.createTimeCombo.findData(current_ct)
        self.createTimeCombo.setCurrentIndex(idx if idx >= 0 else 0)
        self.createTimeCombo.blockSignals(False)
        # 若存在上一轮的选择，从设置恢复
        self._restore_filters()

    def _save_filters(self) -> None:
        self._settings.setValue("filter/method", self.methodCombo.currentData() or "")
        self._settings.setValue("filter/module", self.moduleCombo.currentData() or "")

    def _restore_filters(self) -> None:
        method = self._settings.value("filter/method", "", str)
        module = self._settings.value("filter/module", "", str)
        idx_m = self.methodCombo.findData(method)
        if idx_m >= 0:
            self.methodCombo.setCurrentIndex(idx_m)
        idx_mod = self.moduleCombo.findData(module)
        if idx_mod >= 0:
            self.moduleCombo.setCurrentIndex(idx_mod)

    # ---------- 工具：将 ISO8601/字符串时间转换成本地可读时间 ----------
    def _to_local_display_time(self, iso_text: str) -> str:
        # 常见格式：2025-09-24T07:35:45.000+0000 或 2025-09-24T07:35:45+00:00
        text = (iso_text or "").strip()
        if not text:
            return ""
        try:
            # 统一 +0000 => +00:00
            norm = text
            if len(text) >= 5 and (text.endswith("+0000") or text.endswith("-0000")):
                norm = text[:-5] + text[-5:-2] + ":" + text[-2:]
            dt = _dt.datetime.fromisoformat(norm.replace("Z", "+00:00"))
            # 若无 tzinfo，按本地时间返回
            if dt.tzinfo is None:
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            local_dt = dt.astimezone()
            return local_dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return text

    def _on_click_start_auto(self) -> None:
        seconds = int(self.refreshSpin.value())
        self._timer.setInterval(max(1, seconds) * 1000)
        if not self._timer.isActive():
            self._timer.start()
        self._ok("已启动自动刷新")

    def _on_click_stop_auto(self) -> None:
        if self._timer.isActive():
            self._timer.stop()
        self._status.showMessage("已停止自动刷新", 2000)

    def _on_timer_tick(self) -> None:
        # 根据选择的数据源执行自动刷新
        src = self.refreshSourceCombo.currentText()
        if src.startswith("抓取"):
            self._on_click_fetch()
        else:
            self._on_click_query()

    def _on_click_export(self) -> None:
        text = self.logView.toPlainText()
        if not text:
            self._warn("没有可导出的内容。")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出日志", "logs.txt", "Text Files (*.txt)"
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
                self._ok("导出成功。")
            except OSError as exc:
                self._error(f"导出失败：{exc}")

    def _on_click_clear(self) -> None:
        self.logView.clear()
        self._raw_text = ""
        self._status.showMessage("已清空", 1500)

    # --------------------- 过滤与显示 ---------------------
    _raw_text: str = ""

    def _apply_filter_and_show(self) -> None:
        text = self._raw_text or ""
        pattern = self.regexEdit.text().strip()
        if not text:
            self._lines_all = []
            self._window_start = 0
            self._window_end = 0
            self.logView.setPlainText("")
            return

        # 计算内容哈希，避免重复渲染
        new_hash = hash(text)

        # 编译/复用正则
        compiled = None
        if pattern:
            try:
                flags = re.IGNORECASE if self.caseCheck.isChecked() else 0
                if (
                    self._compiled_regex is not None
                    and self._last_compiled_pattern == pattern
                    and self._last_compiled_flags == flags
                ):
                    compiled = self._compiled_regex
                else:
                    compiled = re.compile(pattern, flags)
                    self._compiled_regex = compiled
                    self._last_compiled_pattern = pattern
                    self._last_compiled_flags = flags
            except re.error as exc:
                self._error(f"正则错误：{exc}")
                return

        # 结构化过滤：基于 method 与 module 从 records 中生成文本（若可用）
        selected_method = self.methodCombo.currentData() or ""
        selected_module = self.moduleCombo.currentData() or ""
        structured_lines = None
        try:
            # 如果上一轮收到过 records，则按筛选生成
            if self._last_records_for_filters:
                buf: list[str] = []
                # 解析 createTime 精确筛选
                select_ct = self.createTimeCombo.currentData() or ""

                for item in self._last_records_for_filters:
                    if not isinstance(item, dict):
                        continue
                    # createTime 等值过滤
                    if select_ct and item.get("createTime") != select_ct:
                        continue
                    if selected_method and item.get("method") != selected_method:
                        continue
                    em = item.get("errorMsg")
                    if isinstance(em, str) and em:
                        try:
                            em_obj = json.loads(em)
                            if isinstance(em_obj, dict):
                                # 仅输出选定模块或全部模块
                                keys = (
                                    [selected_module]
                                    if selected_module
                                    else list(em_obj.keys())
                                )
                                for k in keys:
                                    if not k:
                                        continue
                                    val = em_obj.get(k)
                                    if isinstance(val, list):
                                        buf.extend(str(x).rstrip("\n") for x in val)
                                    elif isinstance(val, str):
                                        buf.extend(val.splitlines())
                            else:
                                # JSON 不是 dict（可能是 list/标量），未指定模块时整体纳入
                                if not selected_module:
                                    if isinstance(em_obj, list):
                                        buf.extend(str(x).rstrip("\n") for x in em_obj)
                                    else:
                                        buf.extend(str(em).splitlines())
                        except (json.JSONDecodeError, ValueError, TypeError):
                            # 非 JSON 文本，未指定模块时整体纳入
                            if not selected_module:
                                buf.extend(em.splitlines())
                structured_lines = buf
        except (TypeError, AttributeError):
            structured_lines = None

        # 先确定基础行集（结构化优先；否则原始文本分行）
        if structured_lines is None or len(structured_lines) == 0:
            base_lines = text.splitlines()
        else:
            base_lines = structured_lines

        # 再进行正则后置过滤
        if compiled is None:
            all_lines = base_lines
        else:
            all_lines = [ln for ln in base_lines if compiled.search(ln)]
        self._lines_all = all_lines

        # 仅取窗口：默认显示最后 max_lines 行
        max_lines = int(self.maxLinesSpin.value())
        end = len(all_lines)
        start = max(0, end - max_lines)
        self._window_start = start
        self._window_end = end
        window_lines = all_lines[start:end]
        new_text = "\n".join(window_lines)

        # 仅当文本不同再刷新，减少闪烁
        if new_text != self.logView.toPlainText() or new_hash != self._last_shown_hash:
            scrollbar = self.logView.verticalScrollBar()
            at_bottom = (
                scrollbar.value() >= scrollbar.maximum() - 2 if scrollbar else False
            )

            self.logView.setPlainText(new_text)
            self._last_shown_hash = new_hash

            if at_bottom:
                scrollbar.setValue(scrollbar.maximum())

        self._status.showMessage(
            f"显示行数：{len(window_lines)} / 总行数：{len(all_lines)}", 1500
        )

    def _on_log_scroll(self, _val: int) -> None:
        # 仅当滚动到顶部时，尝试向上扩展窗口
        if self._in_scroll_update:
            return
        sb = self.logView.verticalScrollBar()
        if not sb or sb.value() > sb.minimum():
            return
        if not self._lines_all:
            return

        # 计算向上扩展量（改为窗口滑动：保持窗口大小为 max_lines，整体上移）
        grow = min(self._chunk_lines, self._window_start)
        if grow <= 0:
            return

        max_lines = int(self.maxLinesSpin.value())
        new_start = max(0, self._window_start - grow)
        # 窗口大小尽量保持在 max_lines
        new_end = min(len(self._lines_all), new_start + max_lines)
        # 若剩余不足 max_lines，则尽量扩到最早
        if new_start == 0:
            new_end = min(len(self._lines_all), max_lines)

        window_lines = self._lines_all[new_start:new_end]
        new_text = "\n".join(window_lines)

        # 记录旧滚动状态，用于平滑过渡
        # 顶部扩展：保持视图仍接近顶部，便于连续上滑加载
        # 这里将滚动值设置为一个很小的值而非 0，避免重复触发

        self._in_scroll_update = True
        try:
            self.logView.setPlainText(new_text)
            self._window_start = new_start
            self._window_end = new_end
            # 把视口保持在加载前的位置附近：将滚动条置顶附近，避免反复触发但保留用户继续上滑
            sb.setValue(min(sb.maximum(), sb.minimum() + 2))
        finally:
            self._in_scroll_update = False

    # --------------------- 统一反馈 ---------------------
    def _ok(self, message: str) -> None:
        self._status.showMessage(message, 2000)

    def _warn(self, message: str) -> None:
        self._status.showMessage(message, 3000)
        QMessageBox.warning(self, "提示", message)

    def _error(self, message: str) -> None:
        self._status.showMessage(message, 5000)
        QMessageBox.critical(self, "错误", message)

    def _on_debug_message(self, message: str) -> None:
        if self.debugCheck.isChecked():
            # 仅在开启时弹窗提示，同时写入状态栏
            self._status.showMessage(message, 5000)
            QMessageBox.information(self, "调试", message)

    # --------------------- 展开/还原 日志区域 ---------------------
    def _on_toggle_expand(self, checked: bool) -> None:
        # 根据状态隐藏/显示其他分组，最大化日志可视区域
        for grp in getattr(self, "_groups_for_expand", []):
            grp.setVisible(not checked)
        self.expandBtn.setText("还原布局" if checked else "展开日志")
        # 提示并微调状态栏
        self._status.showMessage("已展开日志区域" if checked else "已还原布局", 2000)


def main() -> None:
    app = QApplication([])
    win = MainWindow()
    win.resize(1000, 700)
    win.show()
    app.exec()


if __name__ == "__main__":
    main()
