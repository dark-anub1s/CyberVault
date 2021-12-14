#!/usr/bin/env python3
import sys
import qrcode
import sqlite3
from pathlib import Path
from PyQt5.uic import loadUi
from functions import generate_keys
from PyQt5 import QtWidgets
from PyQt5 import QtCore
from pyotp import random_base32, TOTP
from database import create_db, create_cybervault
from PIL.ImageQt import ImageQt
from PyQt5.QtGui import QPixmap, QImage
from PyQt5.QtWidgets import QMainWindow, QApplication, QDialog, QFileDialog, QWidget


# Done
class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()
        loadUi("cybervault.ui", self)
        self.setFixedSize(960, 540)
        create_db()
        self.app_open()
        self.new_account.clicked.connect(self.create_account)
        self.import_cybervault.clicked.connect(self.open_vault)
        self.login_to_account.clicked.connect(self.login)

        # self.exit_app.triggered.connect(exit_handler)

    def app_open(self):
        pass

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
        # Setup QR Code Generator Window variable
        self.qrcodewindow = None
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
        self.s_key = None
        self.account = False

    def enable_mfa(self):
        username = self.username.text()
        self.checked = self.enableMFA.isChecked()
        self.s_key = random_base32()
        totp = TOTP(self.s_key)
        auth = totp.provisioning_uri(name=username, issuer_name='CyberVault')

        if self.qrcodewindow is None:
            self.qrcodewindow = QRCodeGenerator(auth, self.s_key)


        self.qrcodewindow.show()


    def create_account(self):
        username = self.username.text()
        self.pri_key, self.pub_key = generate_keys()
        self.save_key()
        self.get_vault_name()

        if self.checked:
            # Create account in database and make password vault with MFA
            create_cybervault(username, self.pub_key, self.vault, self.s_key)
            self.account = True
        else:
            create_cybervault(username, self.pub_key, self.vault)
            self.account = True

        if self.account:
            passvault = PasswordVault(self.vault)
            widget.addWidget(passvault)
            widget.setCurrentIndex(widget.currentIndex()+1)

    def save_key(self):
        fname = QFileDialog.getSaveFileName(self, "Save Key", "",
                                            'Key File (*.pem)')
        if fname == ('', ''):
            pass
        else:
            file = fname[0]
            with open(file, 'wb') as f:
                f.write(self.pri_key)
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

        self.login_btn.clicked.connect(self.login)

    def login(self):
        passvault = PasswordVault('C:/Users/anubis/Documents/Vault_testing/thiggins.cvdb')
        widget.addWidget(passvault)
        widget.setCurrentIndex(widget.currentIndex()+1)


class OpenCyberVault(QDialog):
    def __init__(self):
        super(OpenCyberVault, self).__init__()
        loadUi("opencybervault.ui", self)
        self.main_menu_button.clicked.connect(self.back_to_main)

    def back_to_main(self):
        widget.setCurrentIndex(widget.currentIndex()-1)


class PasswordGenerator(QWidget):
    def __init__(self):
        super(PasswordGenerate, self).__init__()
        loadUi("password.ui", self)


class QRCodeGenerator(QWidget):
    def __init__(self, auth_string, s_key):
        super(QRCodeGenerator, self).__init__()
        loadUi("qrpopup.ui", self)
        self.auth = auth_string
        self.img = qrcode.make(self.auth)
        self.qr = ImageQt(self.img)
        self.verify_btn.clicked.connect(lambda: self.verifyotp(s_key))
        self.setWindowFlag(QtCore.Qt.WindowCloseButtonHint, False)

        pix = QPixmap.fromImage(self.qr)

        self.qrcode_label.setPixmap(pix)

    def verifyotp(self, s_key):
        mfa_totp = TOTP(s_key)
        current = self.otp_entry.text()


        if mfa_totp.verify(current):
            self.close()

class PasswordVault(QDialog):
    def __init__(self, vault):
        super(PasswordVault, self).__init__()
        loadUi("passwordvault.ui", self)
        self.vault_path = Path(vault)
        # self.account_table.setHorizontalHeaderLabels(["Website", "Entry Name", "Username", "Password"])
        self.loadlist()
        self.account_list.clicked.connect(self.loadtable)

    def loadlist(self):
        self.conn = sqlite3.connect(self.vault_path)
        self.cur = self.conn.cursor()

        self.cur.execute("""SELECT name FROM cybervault""")
        names = self.cur.fetchall()

        for i in range(len(names)):
            entry = QtWidgets.QListWidgetItem(names[i][0])
            self.account_list.addItem(entry)

    def loadtable(self):
        self.account_table.setRowCount(15)
        self.account_table.setColumnCount(4)
        self.account_table.setColumnWidth(0, 150)
        self.account_table.setColumnWidth(1, 200)
        self.account_table.setColumnWidth(2, 150)
        self.account_table.setColumnWidth(3, 350)
        self.account_table.clear()
        account_indexes = []
        delegate = PasswordDelegate(self.account_table)
        self.account_table.setItemDelegate(delegate)
        table_len = 0
        request = self.account_list.currentItem()

        results = self.cur.execute("SELECT * FROM cybervault WHERE name=? LIMIT 15", (request.text(),))
        tablerow = 0
        for row in results:
            account_indexes.append(row[0])
            self.account_table.setItem(tablerow, 0, QtWidgets.QTableWidgetItem(row[0]))
            self.account_table.setItem(tablerow, 1, QtWidgets.QTableWidgetItem(row[1]))
            self.account_table.setItem(tablerow, 2, QtWidgets.QTableWidgetItem(row[2]))
            self.account_table.setItem(tablerow, 3, QtWidgets.QTableWidgetItem(row[3]))

            tablerow += 1


class PasswordDelegate(QtWidgets.QStyledItemDelegate):
    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        if index.column() == 3:
            style = option.widget.style() or QtWidgets.QApplication.style()
            hint = style.styleHint(QtWidgets.QStyle.SH_LineEdit_PasswordCharacter)
            option.text = chr(hint) * len(option.text)

def exit_handler():
    print("Exiting Now")
    sys.exit(0)


if __name__ == '__main__':
    app = QApplication([])
    app.aboutToQuit.connect(exit_handler)
    widget = QtWidgets.QStackedWidget()
    mainwindow = UI()
    widget.addWidget(mainwindow)
    widget.show()
    app.exec_()
