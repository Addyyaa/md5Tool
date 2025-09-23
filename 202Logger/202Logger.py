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
from typing import Optional

from PySide6.QtCore import (
    QObject,
    QSettings,
    QTimer,
    QUrl,
    QUrlQuery,
    QByteArray,
    Signal,
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

        reply = self._manager.get(request)
        request.setRawHeader(b"Accept", b"application/json")
        self._attach_handlers(reply)
        # 调试：抓取请求预览
        self._debug(f"抓取请求 GET -> {url.toString()}")
        reply.finished.connect(lambda r=reply: self._handle_logs_reply(r))

    def _handle_logs_reply(self, reply: QNetworkReply) -> None:  # type: ignore[no-untyped-def]
        status = reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)
        reason = reply.attribute(QNetworkRequest.HttpReasonPhraseAttribute)
        data_text = bytes(reply.readAll()).decode("utf-8", errors="ignore")

        # 即便 Qt 报 Unknown error，只要 HTTP 200/206 且拿到内容，优先展示日志
        if data_text and (not reply.error() or status in (200, 206)):
            self.logsFetched.emit(data_text)
            self._debug(f"抓取成功 HTTP {status} {reason}，长度 {len(data_text)}")
            reply.deleteLater()
            return

        extra = f" (HTTP {status} {reason})" if status else ""
        snippet = ("；响应体：" + data_text[:300]) if data_text else ""
        self.requestFailed.emit(f"抓取失败：{reply.errorString()}{extra}{snippet}")
        self._debug(f"抓取失败 HTTP {status} {reason}：{data_text[:300]}")
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

        # 自动刷新定时器
        self._timer = QTimer(self)
        self._timer.setInterval(5000)
        self._timer.timeout.connect(self._on_timer_tick)

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

        # 分组：刷新与过滤
        grp_tools = QGroupBox("刷新与过滤", self)
        grid_tools = QGridLayout(grp_tools)

        self.refreshSpin = QSpinBox()
        self.refreshSpin.setRange(1, 3600)
        self.refreshSpin.setValue(5)
        grid_tools.addWidget(QLabel("自动刷新(秒)"), 0, 0)
        grid_tools.addWidget(self.refreshSpin, 0, 1)

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

        # 分组：操作
        grp_actions = QGroupBox("操作", self)
        grid_actions = QGridLayout(grp_actions)

        btn_export = QPushButton("导出为文件…")
        btn_clear = QPushButton("清空显示")
        btn_export.clicked.connect(self._on_click_export)
        btn_clear.clicked.connect(self._on_click_clear)
        grid_actions.addWidget(btn_export, 0, 0)
        grid_actions.addWidget(btn_clear, 0, 1)

        # 日志显示
        self.logView = QPlainTextEdit()
        self.logView.setReadOnly(True)
        self.logView.setLineWrapMode(QPlainTextEdit.NoWrap)

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
        layout.addWidget(grp_tools, 2, 0, 1, 2)
        layout.addWidget(grp_actions, 3, 0, 1, 2)
        layout.addWidget(self.logView, 4, 0, 1, 2)
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
        self._status.showMessage("正在抓取日志…", 2000)
        self._api.fetch_logs(device_id, log_path)

    def _on_logs_fetched(self, text: str) -> None:
        self._status.showMessage("日志抓取成功", 2000)
        self._raw_text = text  # 原始文本用于过滤
        self._apply_filter_and_show()

    def _on_request_failed(self, message: str) -> None:
        self._error(message)

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
        # 自动调用抓取逻辑
        self._on_click_fetch()

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
            self.logView.setPlainText("")
            return
        if not pattern:
            self.logView.setPlainText(text)
            return
        try:
            flags = re.IGNORECASE if self.caseCheck.isChecked() else 0
            compiled = re.compile(pattern, flags)
            lines = text.splitlines()
            matched = [ln for ln in lines if compiled.search(ln)]
            self.logView.setPlainText("\n".join(matched))
            self._status.showMessage(f"过滤后行数：{len(matched)}", 2000)
        except re.error as exc:
            self._error(f"正则错误：{exc}")

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


def main() -> None:
    app = QApplication([])
    win = MainWindow()
    win.resize(1000, 700)
    win.show()
    app.exec()


if __name__ == "__main__":
    main()
