import os
import importlib
from collections import OrderedDict
from dataclasses import dataclass
from typing import List, Optional, Tuple

from PySide6 import QtCore, QtGui, QtWidgets


# =============== 依赖延迟加载（避免静态检查导入错误） ===============
PSDImage = None  # type: ignore[assignment]
Image = None  # type: ignore[assignment]
ImageQt = None  # type: ignore[assignment]

# 支持的主流图片扩展名（小写）
SUPPORTED_IMAGE_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".bmp",
    ".gif",
    ".webp",
    ".tif",
    ".tiff",
}


def load_dependencies() -> None:
    """延迟加载 psd-tools 与 Pillow，避免静态导入报错。"""
    global PSDImage, Image, ImageQt
    if PSDImage is None:
        try:
            psd_tools_mod = importlib.import_module("psd_tools")
            PSDImage = getattr(psd_tools_mod, "PSDImage", None)
        except ImportError:
            PSDImage = None
    if Image is None or ImageQt is None:
        try:
            pil_img = importlib.import_module("PIL.Image")
            pil_imgqt = importlib.import_module("PIL.ImageQt")
            Image = pil_img
            ImageQt = getattr(pil_imgqt, "ImageQt", None)
        except ImportError:
            Image = None
            ImageQt = None


# ======================== LRU 缓存 ========================
class ImageCacheLRU:
    """简单的 QImage LRU 缓存（按文件路径作为 key）。"""

    def __init__(self, capacity: int = 16) -> None:
        self.capacity = max(2, capacity)
        self._cache: "OrderedDict[str, QtGui.QImage]" = OrderedDict()

    def get(self, key: str) -> Optional[QtGui.QImage]:
        img = self._cache.get(key)
        if img is not None:
            self._cache.move_to_end(key)
        return img

    def put(self, key: str, img: QtGui.QImage) -> None:
        self._cache[key] = img
        self._cache.move_to_end(key)
        if len(self._cache) > self.capacity:
            self._cache.popitem(last=False)


# ======================== 工具函数 ========================
def pil_to_qimage(pil_img: object) -> QtGui.QImage:
    """Pillow Image -> QImage（优先使用 ImageQt）。"""
    if ImageQt is not None:
        qimg = ImageQt(pil_img)  # type: ignore[misc]
        if isinstance(qimg, QtGui.QImage):
            return qimg
    # 兜底：转 RGBA，再构造 QImage（避免过度拷贝）
    pil_rgba = pil_img.convert("RGBA")  # type: ignore[attr-defined]
    data = pil_rgba.tobytes("raw", "RGBA")  # type: ignore[call-arg]
    w, h = pil_rgba.size  # type: ignore[attr-defined]
    qimg = QtGui.QImage(data, w, h, QtGui.QImage.Format.Format_RGBA8888)
    return qimg.copy()  # 拷贝到 Qt 管理的缓冲区


def ensure_dependencies(parent: QtWidgets.QWidget) -> bool:
    load_dependencies()
    if PSDImage is None or Image is None:
        QtWidgets.QMessageBox.critical(
            parent,
            "缺少依赖",
            "运行需要安装依赖:\n\n"
            "pip install psd-tools pillow\n\n"
            "安装后重启程序。",
        )
        return False
    return True


# ======================== 后台加载任务 ========================
class PsdLoadSignals(QtCore.QObject):
    finished = QtCore.Signal(str, object, str)  # path, QImage|None, error_message


class PsdLoadTask(QtCore.QRunnable):
    def __init__(self, path: str, signals: PsdLoadSignals) -> None:
        super().__init__()
        self.path = path
        self.signals = signals
        self.setAutoDelete(True)

    @QtCore.Slot()
    def run(self) -> None:
        err = ""
        img: Optional[QtGui.QImage] = None
        try:
            load_dependencies()
            ext = os.path.splitext(self.path)[1].lower()
            if ext == ".psd":
                if PSDImage is None:
                    raise RuntimeError("缺少依赖：psd-tools")
                if Image is None:
                    raise RuntimeError("缺少依赖：pillow（用于图像桥接）")
                psd = PSDImage.open(self.path)  # type: ignore[call-arg, attr-defined]
                pil_img = psd.composite()
                img = pil_to_qimage(pil_img)
            else:
                if Image is None:
                    raise RuntimeError("缺少依赖：pillow")
                pil_img = Image.open(self.path)  # type: ignore[attr-defined]
                if getattr(pil_img, "is_animated", False):
                    try:
                        pil_img.seek(0)
                    except Exception:
                        pass
                img = pil_to_qimage(pil_img)
        except (OSError, ValueError, RuntimeError) as e:
            err = str(e)
        self.signals.finished.emit(self.path, img, err)


# ======================== 主窗口 ========================
@dataclass
class CurrentImage:
    path: str
    image: Optional[QtGui.QImage]


class ImageView(QtWidgets.QLabel):
    """用于显示图片的快速视图（保持比例，快速缩放）。"""

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.setBackgroundRole(QtGui.QPalette.ColorRole.Base)
        self.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Expanding,
        )
        self._source: Optional[QtGui.QImage] = None
        self._fitToWindow: bool = True
        self._scale: float = 1.0

    def setImage(self, img: Optional[QtGui.QImage]) -> None:
        self._source = img
        self._offset = QtCore.QPointF(0.0, 0.0)
        if self._fitToWindow:
            self._scale = 1.0
        self._render()

    def clearImage(self) -> None:
        self._source = None
        self.clear()

    def resizeEvent(self, event: QtGui.QResizeEvent) -> None:  # noqa: N802 - Qt 命名
        super().resizeEvent(event)
        self._render()

    def _render(self) -> None:
        if not self._source or self.width() <= 0 or self.height() <= 0:
            self.clear()
            return
        self.update()

    def paintEvent(self, event: QtGui.QPaintEvent) -> None:  # noqa: N802
        super().paintEvent(event)
        if not self._source:
            return
        painter = QtGui.QPainter(self)
        sw = float(self._source.width())
        sh = float(self._source.height())
        if sw <= 0 or sh <= 0:
            return
        if self._fitToWindow:
            scale = min(self.width() / sw, self.height() / sh)
            dw = sw * scale
            dh = sh * scale
            x = (self.width() - dw) * 0.5
            y = (self.height() - dh) * 0.5
        else:
            scale = float(self._scale)
            dw = sw * scale
            dh = sh * scale
            base_x = (self.width() - dw) * 0.5
            base_y = (self.height() - dh) * 0.5
            x = base_x + self._offset.x()
            y = base_y + self._offset.y()
        target = QtCore.QRectF(x, y, dw, dh)
        painter.setRenderHint(QtGui.QPainter.RenderHint.SmoothPixmapTransform, False)
        painter.drawImage(target, self._source)

    def setFitToWindow(self, on: bool) -> None:
        self._fitToWindow = on
        if on:
            self._scale = 1.0
        self._render()

    def zoomReset(self) -> None:
        self._scale = 1.0
        self._render()

    def zoomRelative(
        self, factor: float, anchor: Optional[QtCore.QPoint] = None
    ) -> None:
        if not self._source:
            return
        if anchor is None:
            anchor = QtCore.QPoint(self.width() // 2, self.height() // 2)
        # 计算缩放前 anchor 对应的图片坐标
        if self._fitToWindow:
            # 切到自由缩放
            self._fitToWindow = False
            self._scale = min(
                self.width() / max(1, self._source.width()),
                self.height() / max(1, self._source.height()),
            )
        sw = float(self._source.width())
        sh = float(self._source.height())
        old_scale = float(self._scale)
        dw_old = sw * old_scale
        dh_old = sh * old_scale
        base_x_old = (self.width() - dw_old) * 0.5
        base_y_old = (self.height() - dh_old) * 0.5
        tl_old_x = base_x_old + self._offset.x()
        tl_old_y = base_y_old + self._offset.y()
        img_x = (anchor.x() - tl_old_x) / max(1e-6, old_scale)
        img_y = (anchor.y() - tl_old_y) / max(1e-6, old_scale)

        # 应用缩放并限制范围
        new_scale = max(0.05, min(20.0, old_scale * factor))
        self._scale = new_scale
        dw_new = sw * new_scale
        dh_new = sh * new_scale
        base_x_new = (self.width() - dw_new) * 0.5
        base_y_new = (self.height() - dh_new) * 0.5
        # 调整偏移，保证同一图像点位于锚点下
        tl_new_x = anchor.x() - img_x * new_scale
        tl_new_y = anchor.y() - img_y * new_scale
        self._offset = QtCore.QPointF(tl_new_x - base_x_new, tl_new_y - base_y_new)
        self._render()

    def wheelEvent(self, event: QtGui.QWheelEvent) -> None:  # noqa: N802
        if event.modifiers() & QtCore.Qt.KeyboardModifier.ControlModifier:
            delta = event.angleDelta().y()
            factor = 1.1 if delta > 0 else 1 / 1.1
            pos = event.position().toPoint()
            self.zoomRelative(factor, anchor=pos)
            event.accept()
            return
        super().wheelEvent(event)

    # 拖拽平移
    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:  # noqa: N802
        if (
            event.button() == QtCore.Qt.MouseButton.LeftButton
            and not self._fitToWindow
            and self._source is not None
        ):
            self._dragging = True
            self._lastMousePos = event.pos()
            self.setCursor(QtCore.Qt.CursorShape.ClosedHandCursor)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QtGui.QMouseEvent) -> None:  # noqa: N802
        if getattr(self, "_dragging", False):
            delta = event.pos() - self._lastMousePos
            self._lastMousePos = event.pos()
            self._offset += QtCore.QPointF(delta)
            self._render()
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QtGui.QMouseEvent) -> None:  # noqa: N802
        if (
            getattr(self, "_dragging", False)
            and event.button() == QtCore.Qt.MouseButton.LeftButton
        ):
            self._dragging = False
            self.setCursor(QtCore.Qt.CursorShape.ArrowCursor)
            event.accept()
            return
        super().mouseReleaseEvent(event)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PSD 预览器 - 高性能")
        self.resize(1200, 800)

        # 状态
        self.files: List[str] = []
        self.index: int = -1
        self.cache = ImageCacheLRU(capacity=24)
        self.threadPool = QtCore.QThreadPool.globalInstance()

        # UI
        central = QtWidgets.QWidget(self)
        outer = QtWidgets.QVBoxLayout(central)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(8)

        # 顶部工具条
        toolbar = QtWidgets.QHBoxLayout()
        toolbar.setSpacing(8)
        self.openBtn = QtWidgets.QPushButton("打开图片（多选）…")
        self.prevBtn = QtWidgets.QPushButton("← 上一张")
        self.nextBtn = QtWidgets.QPushButton("下一张 →")
        self.fitBtn = QtWidgets.QPushButton("适应窗口")
        self.zoomOutBtn = QtWidgets.QPushButton("缩小")
        self.zoomInBtn = QtWidgets.QPushButton("放大")
        self.infoLabel = QtWidgets.QLabel("未加载")
        self.infoLabel.setMinimumWidth(280)
        toolbar.addWidget(self.openBtn)
        toolbar.addStretch(1)
        toolbar.addWidget(self.prevBtn)
        toolbar.addWidget(self.nextBtn)
        toolbar.addSpacing(12)
        toolbar.addWidget(self.fitBtn)
        toolbar.addWidget(self.zoomOutBtn)
        toolbar.addWidget(self.zoomInBtn)
        toolbar.addStretch(1)
        toolbar.addWidget(self.infoLabel)

        # 视图
        self.view = ImageView()
        self.loadingOverlay = QtWidgets.QLabel("加载中…", self.view)
        self.loadingOverlay.setStyleSheet(
            "background: rgba(0,0,0,0.35); color: white; padding: 12px; border-radius: 6px;"
        )
        self.loadingOverlay.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.loadingOverlay.hide()

        outer.addLayout(toolbar)
        outer.addWidget(self.view, 1)
        self.setCentralWidget(central)

        # 连接信号
        self.openBtn.clicked.connect(self.onOpen)
        self.prevBtn.clicked.connect(self.onPrev)
        self.nextBtn.clicked.connect(self.onNext)
        self.fitBtn.clicked.connect(self.onToggleFit)
        self.zoomOutBtn.clicked.connect(lambda: self.view.zoomRelative(1 / 1.1))
        self.zoomInBtn.clicked.connect(lambda: self.view.zoomRelative(1.1))

        # 快捷键（使用 QtGui.QShortcut）
        QtGui.QShortcut(
            QtGui.QKeySequence(QtCore.Qt.Key.Key_Left), self, activated=self.onPrev
        )
        QtGui.QShortcut(
            QtGui.QKeySequence(QtCore.Qt.Key.Key_Right), self, activated=self.onNext
        )
        QtGui.QShortcut(
            QtGui.QKeySequence.ZoomIn,
            self,
            activated=lambda: self.view.zoomRelative(1.1),
        )
        QtGui.QShortcut(
            QtGui.QKeySequence.ZoomOut,
            self,
            activated=lambda: self.view.zoomRelative(1 / 1.1),
        )
        QtGui.QShortcut(
            QtGui.QKeySequence(QtCore.Qt.Key.Key_0), self, activated=self.view.zoomReset
        )

        # 初始化状态
        self._updateNavEnabled()
        self.statusBar().showMessage("打开多个图片后，使用左右方向键或 Ctrl+滚轮 缩放")

    # --------------------- 文件与导航 ---------------------
    def onOpen(self) -> None:
        # 延迟加载依赖，按选择的文件类型决定是否需要 psd-tools / pillow
        filter_str = (
            "所有支持 (*.psd *.png *.jpg *.jpeg *.bmp *.gif *.webp *.tif *.tiff);;"
            "PSD 文件 (*.psd);;图片文件 (*.png *.jpg *.jpeg *.bmp *.gif *.webp *.tif *.tiff);;"
            "所有文件 (*.*)"
        )
        paths, _ = QtWidgets.QFileDialog.getOpenFileNames(
            self, "选择图片（可多选）", "", filter_str
        )
        if not paths:
            return
        # 仅保留存在的文件，排序保证可重复性
        paths = [p for p in paths if os.path.exists(p)]
        paths.sort()
        if not paths:
            return
        supported, dropped_msg = self._filter_supported_by_dependencies(paths)
        if not supported:
            if dropped_msg:
                QtWidgets.QMessageBox.warning(self, "无可用文件", dropped_msg)
            return
        if dropped_msg:
            QtWidgets.QMessageBox.information(self, "部分文件已跳过", dropped_msg)
        self.files = supported
        self.index = 0
        self._updateNavEnabled()
        self._load_current_and_neighbors()

    def _filter_supported_by_dependencies(
        self, paths: List[str]
    ) -> Tuple[List[str], str]:
        load_dependencies()
        supported: List[str] = []
        skipped: List[str] = []
        for p in paths:
            ext = os.path.splitext(p)[1].lower()
            if ext == ".psd":
                if PSDImage is not None:
                    supported.append(p)
                else:
                    skipped.append(f"PSD（缺少 psd-tools）：{os.path.basename(p)}")
            elif ext in SUPPORTED_IMAGE_EXTS:
                if Image is not None:
                    supported.append(p)
                else:
                    skipped.append(f"图片（缺少 pillow）：{os.path.basename(p)}")
            else:
                skipped.append(f"不支持的格式：{os.path.basename(p)}")
        msg = "\n".join(skipped)
        return supported, msg

    def onPrev(self) -> None:
        if self.index > 0:
            self.index -= 1
            self._updateNavEnabled()
            self._load_current_and_neighbors()

    def onNext(self) -> None:
        if self.files and self.index < len(self.files) - 1:
            self.index += 1
            self._updateNavEnabled()
            self._load_current_and_neighbors()

    def _updateNavEnabled(self) -> None:
        total = len(self.files)
        cur = self.index + 1 if self.index >= 0 else 0
        name = (
            os.path.basename(self.files[self.index]) if 0 <= self.index < total else ""
        )
        self.infoLabel.setText(f"{cur}/{total}  {name}")
        self.prevBtn.setEnabled(self.index > 0)
        self.nextBtn.setEnabled(self.index >= 0 and self.index < total - 1)

    # --------------------- 加载与预加载 ---------------------
    def _load_current_and_neighbors(self) -> None:
        if not (0 <= self.index < len(self.files)):
            return
        current_path = self.files[self.index]
        self._load_path(current_path, show_loading=True)
        # 预加载前后
        prev_path = self.files[self.index - 1] if self.index - 1 >= 0 else None
        next_path = (
            self.files[self.index + 1] if self.index + 1 < len(self.files) else None
        )
        if prev_path:
            self._load_path(prev_path, show_loading=False)
        if next_path:
            self._load_path(next_path, show_loading=False)

    def _load_path(self, path: str, show_loading: bool) -> None:
        cached = self.cache.get(path)
        if cached is not None:
            if path == self.files[self.index]:
                self.view.setImage(cached)
                self.loadingOverlay.hide()
                self.statusBar().showMessage("已从缓存加载")
            return

        # 异步加载
        if show_loading and path == self.files[self.index]:
            self._show_overlay(True)
            self.statusBar().showMessage("后台加载中…")

        signals = PsdLoadSignals()
        signals.finished.connect(self._on_loaded)
        task = PsdLoadTask(path, signals)
        self.threadPool.start(task)

    @QtCore.Slot(str, object, str)
    def _on_loaded(
        self, path: str, img: object, err: str
    ) -> None:  # img: Optional[QImage]
        if err:
            # 当前需要显示的图失败时告警
            if self.files and path == self.files[self.index]:
                self._show_overlay(False)
                QtWidgets.QMessageBox.warning(
                    self, "加载失败", f"{os.path.basename(path)}\n\n{err}"
                )
            return

        if isinstance(img, QtGui.QImage):
            self.cache.put(path, img)
            if self.files and path == self.files[self.index]:
                self.view.setImage(img)
                self._show_overlay(False)
                self.statusBar().showMessage("加载完成")

    def _show_overlay(self, on: bool) -> None:
        if on:
            self.loadingOverlay.resize(self.view.size())
            self.loadingOverlay.show()
            self.loadingOverlay.raise_()
        else:
            self.loadingOverlay.hide()

    def onToggleFit(self) -> None:
        # 切换适应窗口/自由缩放
        new_state = not self.view._fitToWindow
        self.view.setFitToWindow(new_state)
        self.fitBtn.setText("适应窗口" if new_state else "自由缩放")


def main() -> None:
    import sys

    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
