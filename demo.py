import hashlib
from queue import Queue
import sys
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import QObject, Signal, Slot, Qt, QThread
from PySide6.QtWidgets import QApplication, QLabel


class Md5Calculator(QObject):
    finished = Signal(bool)

    def __init__(self, result_queue: Queue) -> None:
        super().__init__()
        self.result_queue = result_queue

    @Slot(str)
    def calculate_md5(self, file_path):
        try:
            with open(file_path, "rb") as f:
                md5 = hashlib.md5()
                while True:
                    data = f.read(8192)
                    if not data:
                        break
                    md5.update(data)
            self.result_queue.put(md5.hexdigest())
            self.finished.emit(True)
        except Exception as e:
            print(f"Error calculating MD5 for {file_path}: {e}")
            self.finished.emit(False)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("MD5 Caculator tool")
        self.setGeometry(100, 100, 400, 200)

        self.result_queue = Queue()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        self.status_label = QLabel("等待开始....")
        self.result_label = QLabel("MD5:")
        self.btn_calc = QPushButton("开始计算")

        layout.addWidget(self.status_label)
        layout.addWidget(self.result_label)
        layout.addWidget(self.btn_calc)
        self.btn_calc.clicked.connect(self.start_calc)

        self.thread = None
        self.calculator = None

    def cleanup_worker(self):
        if self.calculator:
            self.calculator.finished.disconnect()
            self.calculator.deleteLater()
            self.calculator = None
        if self.thread:
            self.thread.quit()
            self.thread.wait(2000)
            self.thread.deleteLater()
            self.thread = None

    def start_calc(self):
        if self.thread and self.thread.isRunning():
            self.cleanup_worker()

        self.status_label.setText("计算中....")
        self.btn_calc.setEnabled(False)

        self.thread = QThread()
        self.calculator = Md5Calculator(self.result_queue)
        self.calculator.moveToThread(self.thread)

        self.thread.started.connect(lambda: self.calculator.calculate_md5("demo.py"))
        self.calculator.finished.connect(self.on_finished)

        self.thread.start()

    def on_finished(self, result: bool):
        if result:
            self.check_queue_result()
        else:
            self.status_label.setText("计算失败")
            self.btn_calc.setEnabled(True)

    def check_queue_result(self):
        try:
            result = self.result_queue.get_nowait()
            self.result_label.setText(f"结果：{result}")
            self.status_label.setText("计算完成")
            self.btn_calc.setEnabled(True)
        except:
            # 如果队列为空，延迟后再次尝试
            QTimer.singleShot(100, self.check_queue_result)

    def closeEvent(self, event) -> None:
        self.cleanup_worker()
        event.accept()


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
