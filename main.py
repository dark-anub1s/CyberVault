from PyQt5.uic import loadUi
from PyQt5.QtWidgets import QMainWindow, QApplication



class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()
        loadUi("cybervault.ui", self)
        self.show()


<<<<<<< HEAD
app = QApplication([])
window = UI()
app.exec_()
=======
if __name__ == '__main__':
    app = QApplication([])
    window = UI()
    app.exec_()
>>>>>>> 277fad4031cd3e4a405965960048bd1adb6deada
