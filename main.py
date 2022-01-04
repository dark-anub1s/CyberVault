#!/usr/bin/env python3
import os
import sys
import qrcode
import sqlite3
from pathlib import Path
from PyQt5.uic import loadUi
from functions import generate_keys, pwn_checker, vault_password, rsa_vault_encrypt, aes_encrypt, rsa_vault_decrypt, aes_decrypt
from PyQt5 import QtWidgets
from PyQt5 import QtCore
from pyotp import random_base32, TOTP
from database import create_db, create_cybervault, get_user, add_entry, add_user_enc_data, add_user, get_user_enc_data
from PIL.ImageQt import ImageQt
from PyQt5.QtGui import QPixmap, QImage, QFont, QBrush, QColor
from PyQt5.QtWidgets import QMainWindow, QApplication, QDialog, QFileDialog, QWidget, QMessageBox


# Done
class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()
        loadUi("cybervault.ui", self)
        create_db()
        self.new_account.clicked.connect(self.create_account)
        self.import_cybervault.clicked.connect(self.open_vault)
        self.login_to_account.clicked.connect(self.login)

    def create_account(self):
        newaccountwindow = NewUser()
        widget.addWidget(newaccountwindow)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def login(self):
        loginwindow = Login()
        widget.addWidget(loginwindow)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def open_vault(self):
        openvaultwindow = OpenCyberVault()
        widget.addWidget(openvaultwindow)
        widget.setCurrentIndex(widget.currentIndex()+1)


# Done
class NewUser(QDialog):
    def __init__(self):
        super(NewUser, self).__init__()
        loadUi("newaccount.ui", self)
        self.uname = None
        self.home = Path.home()
        self.vault_state = None
        self.qrcodewindow = None
        self.vault_passwd = None
        self.home = os.path.join(self.home, "Documents")

        # Setting up on screen options
        self.checked = None
        self.enableMFA.stateChanged.connect(self.enable_mfa)
        self.create_account_button.clicked.connect(self.create_account)

        # Setting up key variables
        self.vault = None
        self.s_key = None
        self.pri_key = None
        self.pub_key = None
        self.account = False

    def enable_mfa(self):
        self.uname = self.username.text()
        self.checked = self.enableMFA.isChecked()
        self.s_key = random_base32()
        totp = TOTP(self.s_key)
        auth = totp.provisioning_uri(name=self.uname, issuer_name='CyberVault')

        if self.qrcodewindow is None:
            self.qrcodewindow = QRCodeGenerator(self.s_key, auth)

        self.qrcodewindow.show()

    def create_account(self):
        # Remove option to not have 2FA, once program is 100% functional.
        userid = None
        self.uname = self.username.text()

        self.pri_key, self.pub_key = generate_keys()
        self.save_key()
        self.get_vault_name()
        self.vault_passwd = vault_password()

        result = create_cybervault(self.uname, self.vault)
        if self.checked:
            # Create account in database and make password vault with MFA
            if result:
                self.account = True
                userid = add_user(self.uname, self.pub_key, self.vault, self.s_key)

        else:
            if result:
                self.account = True
                userid = add_user(self.uname, self.pub_key, self.vault)

        session, nonce, tag, ciphertext = rsa_vault_encrypt(self.pub_key, self.vault_passwd)
        if userid: add_user_enc_data(userid, session, nonce, tag, ciphertext)

        if self.account:
            self.open_vault()

    def save_key(self):
        f_name = QFileDialog.getSaveFileName(self, "Save Key", str(self.home),
                                            'Key File (*.pem)')
        if f_name == ('', ''):
            pass
        else:
            file = f_name[0]
            if os.name == 'posix':
                file = f"{file}.pem"

            with open(file, 'wb') as f:
                f.write(self.pri_key)
                f.write(b'\n')

    def get_vault_name(self):
        vault = QFileDialog.getSaveFileName(self, "Save Vault", str(self.home),
                                            'CyberVault Database (*.cvdb)')
        if vault == ('', ''):
            pass
        else:
            self.vault = vault[0]

            if os.name == 'posix':
                self.vault = f"{vault[0]}.cvdb"

    def open_vault(self):
        passvault = PasswordVault(self.vault, self.uname, self.pri_key, enc_vault=True)
        widget.addWidget(passvault)
        widget.setCurrentIndex(widget.currentIndex()+1)


# Done
class Login(QDialog):
    def __init__(self):
        super(Login, self).__init__()
        loadUi("login.ui", self)
        self.username = None
        self.pri_key = None
        self.checked = None
        self.vault = None
        self.otp_s_key = None
        self.home = Path.home()
        self.home = os.path.join(self.home, "Documents")

        self.auth_code_lable.hide()
        self.auth_code_entry.hide()
        self.verify_code_btn.hide()

        self.login_btn.clicked.connect(self.login)
        self.load_rsa_button.clicked.connect(self.load_key)

    def load_key(self):
        f_name = QFileDialog.getOpenFileName(self, 'Load RSA Key', str(self.home), 'Key File (*.pem)')
        self.rsa_key_entry.setText(f_name[0])

    def login(self):
        self.username = self.user_entry.text()
        self.pri_key = self.rsa_key_entry.text()
        self.checked = self.mfa_checkBox.isChecked()

        if self.username:
            user, pub_key, self.vault, self.otp_s_key, userid = get_user(self.username)
            if user:
                # If User has MFA Enabled
                if self.checked and self.otp_s_key:
                    self.login_btn.setEnabled(False)
                    self.auth_code_lable.show()
                    self.auth_code_entry.show()
                    self.verify_code_btn.show()
                    self.verify_code_btn.clicked.connect(self.verify_login)
                # Checks if MFA is enabled but user is not check the box
                elif not self.checked and self.otp_s_key:
                    pass
                # Checks if the box is checked but no opt key was found in database
                elif self.checked and not self.otp_s_key:
                    self.mfa_checkBox.setChecked(False)
                    self.open_vault()
                elif not self.checked and not self.otp_s_key:
                    self.open_vault()
                else:
                    pass

            else:
                pass
        else:
            pass

    def verify_login(self):
        code = self.auth_code_entry.text()
        self.mfa_check = QRCodeGenerator(self.otp_s_key, login=True, current_code=code)
        self.mfa_check.verifyotp()

        result = self.mfa_check.get_verify()
        if result:
            self.open_vault()

    def open_vault(self):
        passvault = PasswordVault(self.vault, self.username, self.pri_key)
        widget.addWidget(passvault)
        widget.setCurrentIndex(widget.currentIndex()+1)


class OpenCyberVault(QDialog):
    def __init__(self):
        super(OpenCyberVault, self).__init__()
        loadUi("opencybervault.ui", self)
        self.main_menu_button.clicked.connect(back_to_main)


class PasswordGenerator(QWidget):
    def __init__(self):
        super(PasswordGenerator, self).__init__()
        loadUi("password.ui", self)


# Done
class QRCodeGenerator(QWidget):
    def __init__(self, s_key, auth_string=None, login=False, current_code=None):
        super(QRCodeGenerator, self).__init__()
        loadUi("qrpopup.ui", self)
        self.verified = None
        self.s_key = s_key
        self.current = current_code
        self.login_to_account = login
        self.setWindowFlag(QtCore.Qt.WindowCloseButtonHint, False)
        self.verify_btn.clicked.connect(self.verify_otp)

        if not self.login_to_account:
            self.auth = auth_string
            self.img = qrcode.make(self.auth)
            self.qr = ImageQt(self.img)
            pix = QPixmap.fromImage(self.qr)
            self.qrcode_label.setPixmap(pix)

    def verify_otp(self):
        mfa_totp = TOTP(self.s_key)
        if not self.login_to_account:
            self.current = self.otp_entry.text()
        else:
            pass

        if mfa_totp.verify(self.current):
            if self.login_to_account:
                self.verified = True

            self.close()

    def get_verify(self):
        return self.verified


# Done
class PasswordVault(QDialog):
    def __init__(self, vault, username, pri_key, enc_vault=False):
        super(PasswordVault, self).__init__()
        loadUi("passwordvault.ui", self)

        # Setup variables needed to run class
        self.conn = None
        self.cur = None
        self.passwd = None
        self.web_url = None
        self.username = None
        self.entry_name = None
        self.pri_key = pri_key
        self.vault_user = None
        self.vault_locked = True
        self.username = username
        self.vault_unlocked = False
        self.vault_path = Path(vault)

        # Get the required info for the current user
        self.get_user()

        # Hide all disabled buttons at start
        self.vault_lock(enc_vault)

        # Setup window entry boxes and buttons to be disabled at start
        self.name_entry.setEnabled(False)
        self.user_entry.setEnabled(False)
        self.submit_btn.setEnabled(False)
        self.add_entry_btn.setEnabled(False)
        self.web_url_entry.setEnabled(False)
        self.password_entry.setEnabled(False)
        self.lock_vault_btn.setEnabled(False)
        self.enable_checkbox.setEnabled(False)
        self.update_entry_btn.setEnabled(False)
        self.delete_entry_btn.setEnabled(False)

        self.account_list.clicked.connect(self.load_table)
        self.add_entry_btn.clicked.connect(self.add_entry)
        self.lock_vault_btn.clicked.connect(lambda: self.vault_lock(enc_vault=True))
        self.unlock_vault_btn.clicked.connect(self.vault_unlock)
        self.enable_checkbox.stateChanged.connect(self.is_checked)

    # Done
    def vault_unlock(self):
        if self.vault_user.unlock_vault():
            # Enable and Disable lock and unlock buttons plus show/hide
            self.lock_vault_btn.show()
            self.unlock_vault_btn.hide()
            self.lock_vault_btn.setEnabled(True)
            self.unlock_vault_btn.setEnabled(False)

            # Display entry boxes and labels.
            self.url_label.show()
            self.user_label.show()
            self.name_entry.show()
            self.user_entry.show()
            self.entry_label.show()
            self.passwd_label.show()
            self.add_entry_btn.show()
            self.web_url_entry.show()
            self.password_entry.show()
            self.lock_vault_btn.show()
            self.enable_checkbox.show()
            self.update_entry_btn.show()
            self.delete_entry_btn.show()

            self.enable_checkbox.setEnabled(True)
            self.enable_checkbox.show()

            self.load_list()

    # Done
    def vault_lock(self, enc_vault):
        if enc_vault:
            self.vault_user.lock_vault()

        self.unlock_vault_btn.setEnabled(True)
        self.unlock_vault_btn.show()

        self.lock_vault_btn.setEnabled(False)
        self.lock_vault_btn.hide()

        # Hide entry boxes and labels.
        self.url_label.hide()
        self.user_label.hide()
        self.name_entry.hide()
        self.user_entry.hide()
        self.submit_btn.hide()
        self.entry_label.hide()
        self.passwd_label.hide()
        self.add_entry_btn.hide()
        self.web_url_entry.hide()
        self.password_entry.hide()
        self.enable_checkbox.hide()
        self.update_entry_btn.hide()
        self.delete_entry_btn.hide()

        self.enable_checkbox.hide()
        self.enable_checkbox.setEnabled(False)

        self.account_list.clear()
        self.account_table.clear()

    # Done
    def get_user(self):
        user, pubkey, vault, s_key, userid = get_user(self.username)
        self.vault_user = User(self.pri_key, pubkey, s_key, vault, userid)

    # Done
    def load_list(self):
        self.account_list.clear()
        self.conn = sqlite3.connect(self.vault_path)
        self.cur = self.conn.cursor()

        self.cur.execute("""SELECT name FROM cybervault""")
        names = self.cur.fetchall()

        for i in range(len(names)):
            entry = QtWidgets.QListWidgetItem(names[i][0])
            self.account_list.addItem(entry)

    # Done
    def load_table(self):
        self.account_table.setRowCount(15)
        self.account_table.setColumnCount(4)
        self.account_table.setColumnWidth(0, 163)
        self.account_table.setColumnWidth(1, 225)
        self.account_table.setColumnWidth(2, 173)
        self.account_table.setColumnWidth(3, 343)
        self.account_table.clear()
        account_indexes = []
        delegate = PasswordDelegate(self.account_table)
        self.account_table.setItemDelegate(delegate)
        request = self.account_list.currentItem()

        results = self.cur.execute("SELECT * FROM cybervault WHERE name=? LIMIT 15", (request.text(),))
        table_row = 0
        for row in results:
            account_indexes.append(row[0])
            self.account_table.setItem(table_row, 0, QtWidgets.QTableWidgetItem(row[1]))
            self.account_table.setItem(table_row, 1, QtWidgets.QTableWidgetItem(row[2]))
            self.account_table.setItem(table_row, 2, QtWidgets.QTableWidgetItem(row[3]))
            self.account_table.setItem(table_row, 3, QtWidgets.QTableWidgetItem(row[4]))

            table_row += 1

    # Done
    def is_checked(self):
        if self.enable_checkbox.isChecked():
            self.entry_enable()
        else:
            self.entry_disable()

    # Done
    def entry_enable(self):
        self.name_entry.setEnabled(True)
        self.web_url_entry.setEnabled(True)
        self.user_entry.setEnabled(True)
        self.password_entry.setEnabled(True)
        self.submit_btn.setEnabled(True)
        self.add_entry_btn.setEnabled(True)

    # Done
    def entry_disable(self):
        self.name_entry.setEnabled(False)
        self.web_url_entry.setEnabled(False)
        self.user_entry.setEnabled(False)
        self.password_entry.setEnabled(False)
        self.submit_btn.setEnabled(False)
        self.add_entry_btn.setEnabled(False)

    # Done
    def add_entry(self):
        self.entry_name = self.name_entry.text()
        self.web_url = self.web_url_entry.text()
        self.username = self.user_entry.text()
        self.passwd = self.password_entry.text()

        if self.entry_name and self.web_url and self.username and self.passwd:
            self.submit_btn.show()
            self.submit_btn.setEnabled(True)
            self.submit_btn.clicked.connect(self.submit_entry)

    # Done
    def submit_entry(self):
        result = add_entry(self.vault_path, self.entry_name, self.web_url, self.username, self.passwd)
        if result:
            self.name_entry.clear()
            self.web_url_entry.clear()
            self.user_entry.clear()
            self.password_entry.clear()
            self.enable_checkbox.setChecked(False)
            self.submit_btn.hide()

            self.load_list()


# Done
class PasswordDelegate(QtWidgets.QStyledItemDelegate):
    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        if index.column() == 3:
            style = option.widget.style() or QtWidgets.QApplication.style()
            hint = style.styleHint(QtWidgets.QStyle.SH_LineEdit_PasswordCharacter)
            option.text = chr(hint) * len(option.text)


# Done
class PasswordChecker(QDialog):
    def __init__(self):
        super(PasswordChecker, self).__init__()
        loadUi("passwordchecker.ui", self)
        self.index_list = []
        self.pass_check_table.setStyleSheet("background-color: rgb(141, 145, 141);")
        self.pass_check_table.setColumnWidth(0, 325)
        self.pass_check_table.setColumnWidth(1, 325)
        self.pass_check_table.setColumnWidth(2, 365)

        self.check_single_pass_btn.clicked.connect(self.check_single_password)
        self.check_vault_pass_btn.clicked.connect(self.check_vault_passwords)
        self.load_vault_btn.clicked.connect(self.create_table)
        self.pass_check_table.clicked.connect(self.get_indexs)

    def create_table(self):
        # vault_path = Path('C:/Users/anubis/Documents/Vault_testing/thiggins.cvdb')
        # vault_path = Path('/home/anubis/Documents/Vault_testing/thiggins.cvdb')
        conn = sqlite3.connect(vault_path)
        self.cur = conn.cursor()

        db = self.cur.execute("""SELECT * FROM cybervault""")
        table_rows = db.fetchall()
        table_rows = len(table_rows)
        self.pass_check_table.setRowCount(table_rows)

        self.load_vault()

    def get_indexs(self):
        self.index_list.append(self.pass_check_table.currentRow())

    def load_vault(self):
        results = self.cur.execute("SELECT * FROM cybervault")
        tablerow = 0
        for row in results:
            self.pass_check_table.setItem(tablerow, 0, QtWidgets.QTableWidgetItem(row[0]))
            self.pass_check_table.setItem(tablerow, 1, QtWidgets.QTableWidgetItem(row[2]))
            self.pass_check_table.setItem(tablerow, 2, QtWidgets.QTableWidgetItem(row[3]))

            tablerow += 1

    def check_single_password(self):
        password = self.single_pass_entry.text()

        result, num = pwn_checker(password)

        if result == True:
            self.single_pass_result_lable.setText(f"Password '{password}' has been compromised {num} times")
            self.single_pass_result_lable.setStyleSheet("background-color: rgb(255, 255, 0);")
        elif result == False:
            self.single_pass_result_lable.setText(f"Password '{password}' is safe to use")
            self.single_pass_result_lable.setStyleSheet("background-color: rgb(144, 238, 144);")

    def check_vault_passwords(self):
        font = QFont()
        font.setBold(True)
        ybrush = QBrush(QColor(255, 255, 0))
        gbrush = QBrush(QColor(144, 238, 144))

        for idx in self.index_list:
            pass_to_check = self.pass_check_table.item(idx, 2).text()
            result, num = pwn_checker(pass_to_check)
            if result:
                self.pass_check_table.item(idx, 0).setFont(font)
                self.pass_check_table.item(idx, 0).setBackground(ybrush)
                self.pass_check_table.item(idx, 1).setFont(font)
                self.pass_check_table.item(idx, 1).setBackground(ybrush)
                self.pass_check_table.item(idx, 2).setFont(font)
                self.pass_check_table.item(idx, 2).setBackground(ybrush)

            elif result == False:
                self.pass_check_table.item(idx, 0).setFont(font)
                self.pass_check_table.item(idx, 0).setBackground(gbrush)
                self.pass_check_table.item(idx, 1).setFont(font)
                self.pass_check_table.item(idx, 1).setBackground(gbrush)
                self.pass_check_table.item(idx, 2).setFont(font)
                self.pass_check_table.item(idx, 2).setBackground(gbrush)

            else:
                pass

        self.index_list.clear()


class BackupAccount(QDialog):
    def __init__(self):
        super(BackupAccount, self).__init__()
        loadUi("backupaccount.ui", self)


class User():
    def __init__(self, prikey, pubkey, s_key, vault, userid):
        self.s_key = s_key
        self.userid = userid
        self.pri_key = prikey
        self.pub_key = pubkey
        self.locked = True
        self.unlocked = False
        self.vault = Path(vault)

    def update_rsa(self):
        pass

    def lock_vault(self):
        passwd = rsa_vault_decrypt(self.pri_key, self.userid)
        aes_encrypt(self.vault, passwd)

    def unlock_vault(self):
        passwd = rsa_vault_decrypt(self.pri_key, self.userid)
        unlocked = aes_decrypt(self.vault, passwd)

        return unlocked


# Done
def back_to_main():
    widget.setCurrentIndex(widget.currentIndex()-1)


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
