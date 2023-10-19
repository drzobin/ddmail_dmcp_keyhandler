from flask import Blueprint, current_app, request
from argon2 import PasswordHasher
import os
import time
import subprocess

from dmcp_keyhandler.validators import is_domain_allowed, is_password_allowed, is_email_allowed

bp = Blueprint("application", __name__, url_prefix="/")

@bp.route("/hash_data", methods=["POST"])
def hash_data():
    if request.method == 'POST':
        ph = PasswordHasher()

        data = request.form.get('data')

        # Validate password.
        if is_password_allowed(data) != True:
            return "error: validation of data failed"

        data_hash = ph.hash(data)

        return data_hash

@bp.route("/create_key", methods=["POST"])
def create_key():
    if request.method == 'POST':
        ph = PasswordHasher()

        email = request.form.get('email')
        key_password = request.form.get('key_password')
        password = request.form.get('password')

        # Validate email.
        if is_email_allowed(email) != True:
            return "error: email validation failed"

        # Validate _keypassword.
        if is_password_allowed(key_password) != True:
            return "error: key_password validation failed"

        # Validate password.
        if is_password_allowed(password) != True:
            return "error: password validation failed"

        # Check if password is correct.
        try:
            if ph.verify(current_app.config["PASSWORD_HASH"], password) != True:
                time.sleep(1)
                return "error: wrong password"
        except:
            time.sleep(1)
            return "error: wrong password"
        time.sleep(1)

        doveadm = current_app.config["DOVEADM_BIN"]

        # Check that doveadm exist.
        if os.path.exists(doveadm) != True:
            return "error: doveadm location is wrong"

        # Create key with password
        output = subprocess.run([doveadm,"-o" "plugin/mail_crypt_private_password="+key_password,"mailbox","cryptokey","generate","-u",email,"-U"], check=True)
        if output.returncode != 0:
            return "error: returncode of cmd doveadm is non zero"

        return "done"

@bp.route("/change_password_on_key", methods=["POST"])
def change_password_on_key():
    if request.method == 'POST':
        ph = PasswordHasher()

        email = request.form.get('email')
        current_key_password = request.form.get('current_key_password')
        new_key_password = request.form.get('new_key_password')
        password = request.form.get('password')

        # Validate email.
        if is_email_allowed(email) != True:
            return "error: email validation failed"

        # Validate current_key_password.
        if is_password_allowed(current_key_password) != True:
            return "error: current_key_password validation failed"

        # Validate new_key_password.
        if is_password_allowed(new_key_password) != True:
            return "error: new_key_password validation failed"

        # Validate password.
        if is_password_allowed(password) != True:
            return "error: password validation failed"

        # Check if password is correct.
        try:
            if ph.verify(current_app.config["PASSWORD_HASH"], password) != True:
                time.sleep(1)
                return "error: wrong password"
        except:
            time.sleep(1)
            return "error: wrong password"
        time.sleep(1)

        doveadm = current_app.config["DOVEADM_BIN"]

        # Check that doveadm exist.
        if os.path.exists(doveadm) != True:
            return "error: doveadm location is wrong"

        # Change password on key.
        output = subprocess.run([doveadm,"mailbox","cryptokey","password","-u",email,"-n",new_key_password,"-o",current_key_password], check=True)
        if output.returncode != 0:
            return "error: returncode of cmd doveadm is non zero"

        return "done"
