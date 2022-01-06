#!/usr/bin/env python3
import os
import sys
import qrcode
import sqlite3
import zipfile
from pathlib import Path
from PyQt5 import QtCore
from PyQt5 import QtWidgets
from PyQt5.uic import loadUi
from PIL.ImageQt import ImageQt
from pyotp import random_base32, TOTP
from PyQt5.QtGui import QPixmap, QFont, QBrush, QColor
from functions import rsa_vault_decrypt, aes_decrypt, clipboard_wipe, clipboard_copy, check_rsa
from PyQt5.QtWidgets import QMainWindow, QApplication, QDialog, QFileDialog, QWidget, QMessageBox
from database import create_db, create_cybervault, get_user, add_entry, add_user_enc_data, add_user, check_passwd
from functions import generate_keys, pwn_checker, vault_password, rsa_vault_encrypt, aes_encrypt, generate_password
from database import get_user_enc_data


# Done
class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()
        loadUi("cybervault.ui", self)
        create_db()
        self.new_account.clicked.connect(self.create_account)
        self.import_cybervault.clicked.connect(self.open_vault)
        self.login_to_account.clicked.connect(self.login)
        self.backup_btn.clicked.connect(self.backup_account)

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

    def backup_account(self):
        account_backup = BackupAccount()
        widget.addWidget(account_backup)
        widget.setCurrentIndex(widget.currentIndex()+1)


# Done
class NewUser(QDialog):
    def __init__(self):
        super(NewUser, self).__init__()
        loadUi("newaccount.ui", self)
        self.img = None
        self.qr = None
        self.uname = None
        self.home = Path.home()
        self.vault_state = None
        self.qrcode = None
        self.vault_passwd = None
        self.home = os.path.join(self.home, "Documents")

        # Setting up onscreen options
        self.auth_code_lable.hide()
        self.code_entry.hide()
        self.verify_code_btn.hide()
        self.create_account_button.hide()
        self.code_entry.setEnabled(False)
        self.verify_code_btn.setEnabled(False)
        self.create_account_button.setEnabled(False)
        self.verify_mfa_btn.clicked.connect(self.setup_mfa)
        self.create_account_button.clicked.connect(self.create_account)

        # Setting up key variables
        self.vault = None
        self.s_key = None
        self.pri_key = None
        self.pub_key = None
        self.account = False

    def setup_mfa(self):
        self.uname = self.username.text()
        self.s_key = random_base32()
        totp = TOTP(self.s_key)
        auth = totp.provisioning_uri(name=self.uname, issuer_name='CyberVault')

        if self.qrcode is None:
            self.img = qrcode.make(auth)
            self.qr = ImageQt(self.img)
            pix = QPixmap.fromImage(self.qr)
            self.qrcode_label.setPixmap(pix)

            self.auth_code_lable.show()
            self.code_entry.show()
            self.verify_code_btn.show()
            self.code_entry.setEnabled(True)
            self.verify_code_btn.setEnabled(True)
            self.verify_code_btn.clicked.connect(self.verify_mfa)

    def verify_mfa(self):
        code = self.code_entry.text()
        self.qrcode = QRCodeGenerator(self.s_key, code)
        self.qrcode.verify()

        if self.qrcode.get_verify():
            self.create_account_button.show()
            self.create_account_button.setEnabled(True)

    def create_account(self):
        userid = None
        self.uname = self.username.text()

        self.pri_key, self.pub_key = generate_keys()
        self.save_key()
        self.get_vault_name()
        self.vault_passwd = vault_password()

        result = create_cybervault(self.uname, self.vault)
        # Create account in database and make password vault with MFA
        if result:
            self.account = True
            userid = add_user(self.uname, self.pub_key, self.vault, self.s_key)

        session, nonce, tag, ciphertext = rsa_vault_encrypt(self.pub_key, self.vault_passwd)
        if userid:
            add_user_enc_data(userid, session, nonce, tag, ciphertext)

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
        self.mfa_check = QRCodeGenerator(self.otp_s_key, code)
        self.mfa_check.verify()

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

        self.tag = None
        self.user = None
        self.file = None
        self.path = None
        self.nonce = None
        self.s_key = None
        self.vault = None
        self.save = None
        self.pubkey = None
        self.userid = None
        self.username = None
        self.temp_pub = None
        self.mfa_check = None
        self.ciphertext = None
        self.session_key = None
        self.backup_vault = None
        self.home = Path.home()
        self.start_location = os.getcwd()
        self.home = os.path.join(self.home, "Documents")

        # Setup buttons
        self.open_btn.clicked.connect(self.open_archive)
        self.browse_btn.clicked.connect(self.get_archive)

    def load_user(self):
        self.username = self.account_entry.text()
        # Get user info from backup db
        self.user, self.pubkey, self.vault, self.s_key, self.userid = get_user(self.username, backup=True, file_path=self.path.parent)
        self.session_key, self.nonce, self.tag, self.ciphertext = get_user_enc_data(self.userid, backup=True, file_path=self.path.parent)

        # Add recovered user to current db
        uid = add_user(self.username, self.pubkey, self.vault, self.s_key)
        add_user_enc_data(uid, self.session_key, self.nonce, self.tag, self.ciphertext)
        os.rename(self.backup_vault, self.vault)
        os.remove(self.file)
        os.remove(os.path.join(self.path.parent, 'backup.db'))

    # Done
    def get_archive(self):
        f_name = QFileDialog.getOpenFileName(self, "Open Vault", str(self.home), 'Backup Archive (*.zip)')
        if f_name == ('', ''):
            pass
        else:
            self.file = f_name[0]
            if os.name == 'posix':
                self.file = f"{f_name[0]}.zip"

            self.path = Path(self.file)
            self.backup_entry.setText(self.file)

    def open_archive(self):
        try:
            with zipfile.ZipFile(self.file, 'r') as backup_archive:
                archive = Path(self.file)
                os.chdir(archive.parent)
                for name in backup_archive.namelist():
                    x = name.split('.')
                    if x[1] == 'cvdb':
                        self.backup_vault = os.path.join(archive.parent, name)
                backup_archive.extractall()

            os.chdir(self.start_location)

        except AttributeError:
            pass

        self.load_user()

    def show_popup(self):
        msg = QMessageBox()

        msg.setWindowTitle("Account Recovery")
        msg.setText("Your account has been successfully recovered!")
        msg.setIcon(QMessageBox.Information)
        msg.setStandardButtons(QMessageBox.Ok)

        msg.buttonClicked.connect(self.popup_button)

        msg.exec_()

    def popup_button(self, i):
        if i.text() == 'OK':
            # Clear and hide buttons and entry boxes
            self.open_btn.hide()
            self.backup_entry.clear()
            self.open_btn.setEnabled(False)

            # Clear data from all properties
            self.tag = None
            self.user = None
            self.file = None
            self.path = None
            self.nonce = None
            self.s_key = None
            self.vault = None
            self.save = None
            self.pubkey = None
            self.userid = None
            self.username = None
            self.temp_pub = None
            self.mfa_check = None
            self.ciphertext = None
            self.session_key = None

            back_to_main()


class PasswordGenerator(QWidget):
    def __init__(self, pass_entry):
        super(PasswordGenerator, self).__init__()
        loadUi("passwordgenerator.ui", self)

        self.slide_value = 11
        self.save_pass = pass_entry
        self.pass_to_use = None
        self.upper = self.upper_checkbox.isChecked()
        self.lower = self.lower_checkbox.isChecked()
        self.num = self.num_checkbox.isChecked()
        self.special = self.special_checkbox.isChecked()
        self.pass_len_value.setText(str(self.slide_value))

        self.copy_pass_btn.clicked.connect(self.use_pass)
        self.gen_pass_btn.clicked.connect(self.pass_generator)
        self.num_checkbox.stateChanged.connect(self.num_select)
        self.upper_checkbox.stateChanged.connect(self.upper_select)
        self.lower_checkbox.stateChanged.connect(self.lower_select)
        self.pass_len_slider.valueChanged.connect(self.slide_change)
        self.special_checkbox.stateChanged.connect(self.special_select)

    def slide_change(self, value):
        self.pass_len_value.setText(str(value))
        self.slide_value = value

    def upper_select(self):
        if self.upper_checkbox.isChecked():
            self.upper = True
        else:
            self.upper = False

    def lower_select(self):
        if self.lower_checkbox.isChecked():
            self.lower = True
        else:
            self.lower = False

    def num_select(self):
        if self.num_checkbox.isChecked():
            self.num = True
        else:
            self.num = False

    def special_select(self):
        if self.special_checkbox.isChecked():
            self.special = True
        else:
            self.special = False

    def pass_generator(self):
        self.pass_to_use = generate_password(self.upper, self.lower, self.num, self.special, self.gen_pass_label, self.slide_value)

    def use_pass(self):
        self.save_pass.setText(self.pass_to_use)


# Done
class QRCodeGenerator(): # QWidget
    def __init__(self, s_key, code):
        # super(QRCodeGenerator, self).__init__()
        # loadUi("qrpopup.ui", self)
        self.s_key = s_key
        self.current = code
        self.verified = None

        # self.setWindowFlag(QtCore.Qt.WindowCloseButtonHint, False)
        # self.verify_btn.clicked.connect(self.verify)

        # if not self.login_to_account:
        #     self.auth = auth_string
        #     self.img = qrcode.make(self.auth)
        #     self.qr = ImageQt(self.img)
        #     pix = QPixmap.fromImage(self.qr)
        #     self.qrcode_label.setPixmap(pix)

    def verify(self):
        mfa_totp = TOTP(self.s_key)

        if mfa_totp.verify(self.current):
            self.verified = True

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
        self.add_to_db = None
        self.username = username
        self.pass_checker = None
        self.vault_unlocked = False
        self.passwd_generator = None
        self.vault_path = Path(vault)

        # Get the required info for the current user
        self.get_user()

        # Hide all disabled buttons at start
        self.vault_lock(enc_vault)

        # Setup window entry boxes and buttons to be disabled at start
        self.copy_btn.setEnabled(False)
        self.name_entry.setEnabled(False)
        self.user_entry.setEnabled(False)
        self.submit_btn.setEnabled(False)
        self.pass_gen_btn.setEnabled(False)
        self.add_entry_btn.setEnabled(False)
        self.web_url_entry.setEnabled(False)
        self.clear_clip_btn.setEnabled(False)
        self.password_entry.setEnabled(False)
        self.check_pass_btn.setEnabled(False)
        self.lock_vault_btn.setEnabled(False)
        self.enable_checkbox.setEnabled(False)
        self.update_entry_btn.setEnabled(False)
        self.delete_entry_btn.setEnabled(False)

        self.pass_gen_btn.clicked.connect(self.pass_gen)
        self.account_list.clicked.connect(self.load_table)
        self.account_table.clicked.connect(self.copy_pass)
        self.add_entry_btn.clicked.connect(self.add_entry)
        self.check_pass_btn.clicked.connect(self.check_pass)
        self.unlock_vault_btn.clicked.connect(self.vault_unlock)
        self.enable_checkbox.stateChanged.connect(self.is_checked)
        self.lock_vault_btn.clicked.connect(lambda: self.vault_lock(enc_vault=True))

    # Done
    def vault_unlock(self):
        if self.vault_user.unlock_vault():
            # Enable and Disable lock and unlock buttons plus show/hide
            self.lock_vault_btn.show()
            self.unlock_vault_btn.hide()
            self.lock_vault_btn.setEnabled(True)
            self.unlock_vault_btn.setEnabled(False)

            # Display entry boxes and labels.
            self.copy_btn.show()
            self.url_label.show()
            self.user_label.show()
            self.name_entry.show()
            self.user_entry.show()
            self.entry_label.show()
            self.passwd_label.show()
            self.pass_gen_btn.show()
            self.add_entry_btn.show()
            self.web_url_entry.show()
            self.clear_clip_btn.show()
            self.password_entry.show()
            self.lock_vault_btn.show()
            self.enable_checkbox.show()
            self.update_entry_btn.show()
            self.delete_entry_btn.show()

            self.check_pass_btn.show()
            self.check_pass_btn.setEnabled(True)

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

        self.copy_btn.setEnabled(False)
        self.pass_gen_btn.setEnabled(False)
        self.clear_clip_btn.setEnabled(False)

        # Hide entry boxes and labels.
        self.copy_btn.hide()
        self.url_label.hide()
        self.user_label.hide()
        self.name_entry.hide()
        self.user_entry.hide()
        self.submit_btn.hide()
        self.entry_label.hide()
        self.passwd_label.hide()
        self.pass_gen_btn.hide()
        self.add_entry_btn.hide()
        self.web_url_entry.hide()
        self.password_entry.hide()
        self.clear_clip_btn.hide()
        self.enable_checkbox.hide()
        self.update_entry_btn.hide()
        self.delete_entry_btn.hide()

        self.enable_checkbox.hide()
        self.enable_checkbox.setEnabled(False)

        self.check_pass_btn.hide()
        self.check_pass_btn.setEnabled(False)

        self.account_list.clear()
        self.account_table.clear()

        clipboard_wipe()

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
        self.pass_gen_btn.setEnabled(True)
        self.copy_btn.setEnabled(True)
        self.clear_clip_btn.setEnabled(True)

    # Done
    def entry_disable(self):
        self.name_entry.setEnabled(False)
        self.web_url_entry.setEnabled(False)
        self.user_entry.setEnabled(False)
        self.password_entry.setEnabled(False)
        self.submit_btn.setEnabled(False)
        self.add_entry_btn.setEnabled(False)
        self.pass_gen_btn.setEnabled(False)
        self.copy_btn.setEnabled(False)
        self.clear_clip_btn.setEnabled(False)

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
        self.add_to_db = check_passwd(self.vault_path, self.passwd)

        if self.add_to_db:
            add_entry(self.vault_path, self.entry_name, self.web_url, self.username, self.passwd)

            self.name_entry.clear()
            self.web_url_entry.clear()
            self.user_entry.clear()
            self.password_entry.clear()
            self.enable_checkbox.setChecked(False)
            self.submit_btn.hide()

            self.load_list()
            self.add_to_db = False
        else:
            self.show_popup()
            self.add_to_db = False

    def copy_pass(self):
        request = self.account_table.currentItem()
        if request:
            clipboard_copy(request.text())

    def pass_gen(self):
        if self.passwd_generator is None:
            self.passwd_generator = PasswordGenerator(self.password_entry)

        self.passwd_generator.show()
        
    def check_pass(self):
        if not self.pass_checker:
            self.pass_checker = PasswordChecker(self.vault_path)

        self.pass_checker.show()

    def show_popup(self):
        msg = QMessageBox()

        msg.setWindowTitle("Password not Unique")
        msg.setText("All passwords entered into the CyberVault need to be unique, please use a different password!")
        msg.setIcon(QMessageBox.Critical)
        msg.setStandardButtons(QMessageBox.Ok)

        msg.buttonClicked.connect(self.popup_button)

        msg.exec_()

    def popup_button(self, i):
        if i.text() == 'OK':
            # Clean up the window to prevent users from clicking the submit button over and over with a bad password.
            self.submit_btn.hide()
            self.password_entry.clear()
            self.submit_btn.setEnabled(False)


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
    def __init__(self, vault):
        super(PasswordChecker, self).__init__()
        loadUi("passwordchecker.ui", self)
        self.index_list = []
        self.conn = sqlite3.connect(vault)
        self.cur = self.conn.cursor()
        self.pass_check_table.setStyleSheet("background-color: rgb(141, 145, 141);")
        self.pass_check_table.setColumnWidth(0, 325)
        self.pass_check_table.setColumnWidth(1, 325)
        self.pass_check_table.setColumnWidth(2, 365)

        self.check_single_pass_btn.clicked.connect(self.check_single_password)
        self.check_vault_pass_btn.clicked.connect(self.check_vault_passwords)
        self.load_vault_btn.clicked.connect(self.create_table)
        self.pass_check_table.clicked.connect(self.get_indexs)

    def create_table(self):
        self.pass_check_table.clear()
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
            self.pass_check_table.setItem(tablerow, 0, QtWidgets.QTableWidgetItem(row[1]))
            self.pass_check_table.setItem(tablerow, 1, QtWidgets.QTableWidgetItem(row[3]))
            self.pass_check_table.setItem(tablerow, 2, QtWidgets.QTableWidgetItem(row[4]))

            tablerow += 1

    def check_single_password(self):
        password = self.single_pass_entry.text()

        result, num = pwn_checker(password)

        if result:
            self.single_pass_result_lable.setText(f"Password '{password}' has been compromised {num} times")
            self.single_pass_result_lable.setStyleSheet("background-color: rgb(255, 255, 0);")
        else:
            self.single_pass_result_lable.setText(f"Password '{password}' is safe to use")
            self.single_pass_result_lable.setStyleSheet("background-color: rgb(144, 238, 144);")

    def check_vault_passwords(self):
        font = QFont()
        font.setBold(True)

        for idx in self.index_list:
            pass_to_check = self.pass_check_table.item(idx, 2).text()
            result, num = pwn_checker(pass_to_check)
            if result:
                brush = QBrush(QColor(255, 255, 0))
            else:
                brush = QBrush(QColor(144, 238, 144))

            self.pass_check_table.item(idx, 0).setFont(font)
            self.pass_check_table.item(idx, 0).setBackground(brush)
            self.pass_check_table.item(idx, 1).setFont(font)
            self.pass_check_table.item(idx, 1).setBackground(brush)
            self.pass_check_table.item(idx, 2).setFont(font)
            self.pass_check_table.item(idx, 2).setBackground(brush)

        self.index_list.clear()


# Done
class BackupAccount(QDialog):
    def __init__(self):
        super(BackupAccount, self).__init__()
        loadUi("backupaccount.ui", self)

        self.tag = None
        self.user = None
        self.file = None
        self.path = None
        self.nonce = None
        self.s_key = None
        self.vault = None
        self.save = None
        self.pubkey = None
        self.userid = None
        self.username = None
        self.temp_pub = None
        self.mfa_check = None
        self.ciphertext = None
        self.session_key = None
        self.home = Path.home()
        self.start_location = os.getcwd()
        self.home = os.path.join(self.home, "Documents")

        # Setup buttons
        self.mfa_verify_btn.clicked.connect(self.mfa)
        self.save_btn.clicked.connect(self.backup_vault)
        self.browse_btn.clicked.connect(self.save_archive)
        self.load_rsa_key_btn.clicked.connect(self.load_rsa)

        # Hide and disable buttons that are not needed right away.
        self.save_btn.hide()
        self.mfa_entry.hide()
        self.mfa_verify_btn.hide()
        self.save_btn.setEnabled(False)
        self.mfa_verify_btn.setEnabled(False)

    def load_rsa(self):
        f_name = QFileDialog.getOpenFileName(self, 'Load RSA Key', str(self.home), 'Key File (*.pem)')
        self.load_rsa_key_entry.setText(f_name[0])
        if self.load_rsa_key_entry.text():
            self.temp_pub = check_rsa(f_name[0])
        self.save_user()

    def save_user(self):
        self.username = self.account_user_entry.text()
        if self.username:
            self.user, self.pubkey, self.vault, self.s_key, self.userid = get_user(self.username)
            if self.temp_pub == self.pubkey:
                self.mfa_entry.show()
                self.mfa_verify_btn.show()
                self.mfa_verify_btn.setEnabled(True)
                if self.userid:
                    self.session_key, self.nonce, self.tag, self.ciphertext = get_user_enc_data(self.userid)
                    create_db(backup=True, file_path=self.path.parent)
                    uid = add_user(self.username, self.pubkey, self.vault, self.s_key, backup=True, file_path=self.path.parent)
                    add_user_enc_data(uid, self.session_key, self.nonce, self.tag, self.ciphertext, backup=True,
                                      file_path=self.path.parent)

                else:
                    pass
            else:
                pass
        else:
            pass

    def mfa(self):
        code = self.mfa_entry.text()
        if code:
            self.mfa_check = QRCodeGenerator(self.s_key, login=True, current_code=code)
            self.mfa_check.verify()

        result = self.mfa_check.get_verify()
        if result:
            self.save_btn.show()
            self.save_btn.setEnabled(True)

    def save_archive(self):
        f_name = QFileDialog.getSaveFileName(self, "Save Vault", str(self.home), 'Backup Archive (*.zip)')
        if f_name == ('', ''):
            pass
        else:
            self.file = f_name[0]
            if os.name == 'posix':
                self.file = f"{f_name[0]}.zip"

            self.path = Path(self.file)
            self.backup_entry.setText(self.file)

    def backup_vault(self):
        backup_db = os.path.join(self.path.parent, 'backup.db')
        with zipfile.ZipFile(self.file, 'w') as backup_archive:
            vault_path = Path(self.vault)
            path = vault_path.parent
            os.chdir(path)
            file = os.path.basename(self.vault)
            backup_archive.write(file)
            os.chdir(self.path.parent)
            file2 = os.path.basename(backup_db)
            backup_archive.write(file2)

        os.remove(backup_db)
        os.chdir(self.start_location)
        self.show_popup()

    def show_popup(self):
        msg = QMessageBox()

        msg.setWindowTitle("Account Backed up")
        msg.setText("""Your account has been successfully backed up! Please keep it somewhere safe and never store
it in the same location as your private key!""")
        msg.setIcon(QMessageBox.Information)
        msg.setStandardButtons(QMessageBox.Ok)

        msg.buttonClicked.connect(self.popup_button)

        msg.exec_()

    def popup_button(self, i):
        if i.text() == 'OK':
            # Clear and hide buttons and entry boxes
            self.save_btn.hide()
            self.mfa_entry.hide()
            self.mfa_entry.clear()
            self.backup_entry.clear()
            self.mfa_verify_btn.hide()
            self.load_rsa_key_entry.clear()
            self.account_user_entry.clear()
            self.save_btn.setEnabled(False)
            self.mfa_verify_btn.setEnabled(False)

            # Clear data from all properties
            self.tag = None
            self.user = None
            self.file = None
            self.path = None
            self.nonce = None
            self.s_key = None
            self.vault = None
            self.save = None
            self.pubkey = None
            self.userid = None
            self.username = None
            self.temp_pub = None
            self.mfa_check = None
            self.ciphertext = None
            self.session_key = None

            back_to_main()


class User:
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
