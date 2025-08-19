import hashlib
import os
import sys
from dataclasses import dataclass
from typing import Optional

from PySide6.QtCore import QObject, Signal, Slot, Qt, QThread
from PySide6.QtGui import QDragEnterEvent, QDropEvent, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QFileDialog,
    QProgressBar,
    QMessageBox,
)


@dataclass
class Md5Result:
    """MD5 计算结果数据结构。"""

    file_path: str
    md5_hex: str


class Md5Worker(QObject):
    """在后台线程计算文件 MD5，避免阻塞 UI。"""

    progress_changed = Signal(int)
    finished = Signal(object)  # 传递 Md5Result 实例
    failed = Signal(str)
    canceled = Signal()

    def __init__(self) -> None:
        super().__init__()
        self._should_cancel = False

    @Slot()
    def cancel(self) -> None:
        self._should_cancel = True

    @Slot(str)
    def run(self, file_path: str) -> None:
        try:
            if not os.path.isfile(file_path):
                self.failed.emit("文件不存在或不可访问")
                return

            file_size = os.path.getsize(file_path)
            hasher = hashlib.md5()
            bytes_read = 0
            chunk_size = 1024 * 1024  # 1MB

            with open(file_path, "rb") as file_obj:
                while True:
                    if self._should_cancel:
                        self.canceled.emit()
                        return

                    chunk = file_obj.read(chunk_size)
                    if not chunk:
                        break

                    hasher.update(chunk)
                    bytes_read += len(chunk)

                    if file_size > 0:
                        progress = int(bytes_read * 100 / file_size)
                        self.progress_changed.emit(progress)

            self.progress_changed.emit(100)
            self.finished.emit(Md5Result(file_path=file_path, md5_hex=hasher.hexdigest()))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(f"计算失败：{exc}")


class DropArea(QWidget):
    """简易拖拽区域：支持将文件拖入以选择。"""

    file_dropped = Signal(str)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setStyleSheet(
            """
            QWidget {
                border: 2px dashed #999;
                border-radius: 8px;
                padding: 16px;
                color: #666;
            }
            """
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)
        hint = QLabel("将文件拖拽到此处，或点击下方“选择文件”按钮")
        hint.setAlignment(Qt.AlignCenter)
        layout.addWidget(hint)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802 (Qt 命名)
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        urls = event.mimeData().urls()
        if not urls:
            return
        local_path = urls[0].toLocalFile()
        if local_path:
            self.file_dropped.emit(local_path)


class MainWindow(QMainWindow):
    """MD5 工具主窗口。"""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("MD5 校验工具")
        self.setMinimumWidth(560)
        try:
            self.setWindowIcon(QIcon())
        except Exception:
            pass

        # 状态
        self._thread: Optional[QThread] = None
        self._worker: Optional[Md5Worker] = None

        # 视图
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        title = QLabel("MD5 校验工具")
        title.setStyleSheet("font-size: 20px; font-weight: 700; margin-bottom: 4px;")
        root.addWidget(title)

        subtitle = QLabel("选择或拖拽文件，开始计算其 MD5 值并进行校验")
        subtitle.setStyleSheet("color: #666;")
        root.addWidget(subtitle)

        self.drop_area = DropArea()
        self.drop_area.file_dropped.connect(self._on_file_selected)
        root.addWidget(self.drop_area)

        # 文件选择行
        file_row = QHBoxLayout()
        self.input_file = QLineEdit()
        self.input_file.setPlaceholderText("选择或拖入要计算的文件...")
        self.input_file.setReadOnly(True)
        btn_browse = QPushButton("选择文件")
        btn_browse.clicked.connect(self._choose_file)
        file_row.addWidget(self.input_file, 1)
        file_row.addWidget(btn_browse, 0)
        root.addLayout(file_row)

        # 操作按钮
        action_row = QHBoxLayout()
        self.btn_start = QPushButton("开始计算")
        self.btn_start.clicked.connect(self._start_calc)
        self.btn_cancel = QPushButton("取消")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel_calc)
        action_row.addWidget(self.btn_start)
        action_row.addWidget(self.btn_cancel)
        root.addLayout(action_row)

        # 进度条
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        root.addWidget(self.progress)

        # 结果展示
        result_row = QHBoxLayout()
        self.output_md5 = QLineEdit()
        self.output_md5.setPlaceholderText("MD5 结果将显示在此处")
        self.output_md5.setReadOnly(True)
        btn_copy = QPushButton("复制")
        btn_copy.clicked.connect(self._copy_md5)
        result_row.addWidget(self.output_md5, 1)
        result_row.addWidget(btn_copy, 0)
        root.addLayout(result_row)

        # 校验行
        verify_row = QHBoxLayout()
        self.input_expected = QLineEdit()
        self.input_expected.setPlaceholderText("输入期望的 MD5 值进行校验（可选）")
        btn_verify = QPushButton("校验")
        btn_verify.clicked.connect(self._verify_md5)
        self.label_verify = QLabel("")
        verify_row.addWidget(self.input_expected, 1)
        verify_row.addWidget(btn_verify, 0)
        verify_row.addWidget(self.label_verify, 0)
        root.addLayout(verify_row)

        # 状态
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #666;")
        root.addWidget(self.status_label)

    # ---------- 事件处理 ----------

    @Slot()
    def _choose_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if file_path:
            self._on_file_selected(file_path)

    @Slot(str)
    def _on_file_selected(self, file_path: str) -> None:
        self.input_file.setText(file_path)
        self.status_label.setText("已选择文件，点击“开始计算”或直接校验")

    @Slot()
    def _start_calc(self) -> None:
        file_path = self.input_file.text().strip()
        if not file_path:
            self._alert("请先选择文件")
            return
        if self._thread is not None:
            self._alert("正在计算中，请稍候或取消后重试")
            return

        self.progress.setValue(0)
        self.output_md5.clear()
        self.label_verify.clear()
        self.status_label.setText("正在计算 MD5...")
        self._toggle_controls(busy=True)

        # 启动后台线程
        self._thread = QThread(self)
        self._worker = Md5Worker()
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(lambda: self._worker.run(file_path))
        self._worker.progress_changed.connect(self.progress.setValue)
        self._worker.finished.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.canceled.connect(self._on_canceled)
        self._thread.start()

    @Slot()
    def _cancel_calc(self) -> None:
        if self._worker is not None:
            self._worker.cancel()

    @Slot(object)
    def _on_finished(self, result: object) -> None:
        if isinstance(result, Md5Result):
            md5_hex = result.md5_hex
        else:
            # 回退处理
            try:
                md5_hex = getattr(result, "md5_hex", "")
            except Exception:
                md5_hex = ""
        self.output_md5.setText(md5_hex)
        self.status_label.setText("计算完成")
        self._cleanup_worker()

    @Slot(str)
    def _on_failed(self, message: str) -> None:
        self._alert(message)
        self.status_label.setText("计算失败")
        self._cleanup_worker()

    @Slot()
    def _on_canceled(self) -> None:
        self.status_label.setText("已取消")
        self._cleanup_worker()

    @Slot()
    def _copy_md5(self) -> None:
        text = self.output_md5.text().strip()
        if not text:
            self._alert("无可复制内容")
            return
        QApplication.clipboard().setText(text)
        self.status_label.setText("已复制到剪贴板")

    @Slot()
    def _verify_md5(self) -> None:
        actual = self.output_md5.text().strip().lower()
        expected = self.input_expected.text().strip().lower()
        if not actual:
            self._alert("请先计算 MD5")
            return
        if not expected:
            self._alert("请输入期望的 MD5 值")
            return
        if actual == expected:
            self.label_verify.setText("匹配 ✔")
            self.label_verify.setStyleSheet("color: #0a7; font-weight: 700;")
            self.status_label.setText("校验通过")
        else:
            self.label_verify.setText("不匹配 ✖")
            self.label_verify.setStyleSheet("color: #c33; font-weight: 700;")
            self.status_label.setText("校验失败")

    def _toggle_controls(self, busy: bool) -> None:
        self.btn_start.setEnabled(not busy)
        self.btn_cancel.setEnabled(busy)

    def _cleanup_worker(self) -> None:
        self._toggle_controls(busy=False)
        if self._worker is not None:
            try:
                # 断开信号连接，避免悬挂回调
                self._worker.progress_changed.disconnect()
                self._worker.finished.disconnect()
                self._worker.failed.disconnect()
                self._worker.canceled.disconnect()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(2000)
        self._worker = None
        self._thread = None

    def _alert(self, message: str) -> None:
        QMessageBox.information(self, "提示", message)


def main() -> int:
    """程序入口。"""

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
