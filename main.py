from PyQt5.QtWidgets import *
from PyQt5 import uic

class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()
        uic.loadUi("cybervault.ui", self)
        self.show()

app = QApplication([])
window = UI()
app.exec_()
