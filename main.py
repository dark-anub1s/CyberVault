#!/usr/bin/env python3
from pyqrcode import *
from PyQt5 import QtWidgets
from PyQt5.uic import loadUi
from functions import generate_keys
from pyotp import random_base32, TOTP
from database import create_cybervault
from PyQt5.QtWidgets import QMainWindow, QApplication, QDialog, QFileDialog


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

        # Setting up key variables
        self.pri_key = None
        self.pub_key = None
        self.vault = None

    def enable_mfa(self):
        username = self.username.text()
        self.checked = self.enableMFA.isChecked()
        s_key = random_base32()
        totp = TOTP(s_key)
        auth = totp.provisioning_uri(name=username, issuer_name='CyberVault')

    def create_account(self):
        otp = ""
        username = self.username.text()
        pri_key, pub_key = generate_keys()
        self.save_key(pri_key)
        self.get_vault_name()

        if self.checked:
            # Create account in database and make password vault with MFA
            create_cybervault(username, pub_key, pri_key, self.vault, otp)
        else:
            create_cybervault(username, pub_key, pri_key, self.vault)

    def save_key(self, pri_key):
        fname = QFileDialog.getSaveFileName(self, "Save Key", "",
                                            'Key File (*.pem)')
        if fname == ('', ''):
            pass
        else:
            file = fname[0]
            with open(file, 'wb') as f:
                f.write(pri_key)
                f.write(b'\n')

    def get_vault_name(self):
        vault = QFileDialog.getSaveFileName(self, "Save Vault", "",
                                            'CyberVault Database (*.cvdb)')
        if vault == ('', ''):
            pass
        else:
            self.vault = vault[0]


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
