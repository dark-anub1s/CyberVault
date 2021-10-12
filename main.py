from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMainWindow, QApplication, QDialog


# Done
class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()
        loadUi("cybervault.ui", self)
        self.new_account.clicked.connect(self.create_account)
        self.open_cybervault.clicked.connect(self.open_vault)
        self.login_to_account.clicked.connect(self.login)

    def create_account(self):
        newaccountwindow = New_User()
        widget.addWidget(newaccountwindow)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def open_vault(self):
        openvaultwindow = OpenCyberVault()
        widget.addWidget(openvaultwindow)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def login(self):
        loginwindow = Login()
        widget.addWidget(loginwindow)
        widget.setCurrentIndex(widget.currentIndex()+1)


class New_User(QDialog):
    def __init__(self):
        super(New_User, self).__init__()
        loadUi("newaccount.ui", self)


class Login(QDialog):
    def __init__(self):
        super(Login, self).__init__()
        loadUi("login.ui", self)


class OpenCyberVault(QDialog):
    def __init__(self):
        super(OpenCyberVault, self).__init__()
        loadUi("opencybervault.ui", self)


if __name__ == '__main__':
    app = QApplication([])
    widget = QtWidgets.QStackedWidget()
    mainwindow = UI()
    widget.addWidget(mainwindow)
    widget.show()
    app.exec_()
