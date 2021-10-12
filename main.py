from PyQt5 import QtWidgets
from PyQt5.uic import loadUi
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
        newaccountwindow = NewUser()
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


class NewUser(QDialog):
    def __init__(self):
        super(NewUser, self).__init__()
        loadUi("newaccount.ui", self)

        # Setting up on screen options
        self.checked = None
        self.enableMFA.stateChanged.connect(self.enable_mfa)
        self.create_account_button.clicked.connect(self.create_account)

    def enable_mfa(self):
        self.checked = self.enableMFA.isChecked()

    def create_account(self):
        username = self.username.text()
        if self.checked:
            print("Is checked\n")

            print(f"Username: {username}")
        else:
            print("No MFA\n")
            print(f"Username: {username}")


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
