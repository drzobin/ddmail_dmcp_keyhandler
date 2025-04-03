from flask import Blueprint, current_app, request
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os
import time
import subprocess
import logging

from dmcp_keyhandler.validators import is_domain_allowed, is_password_allowed, is_email_allowed

bp = Blueprint("application", __name__, url_prefix="/")

@bp.route("/hash_data", methods=["POST"])
def hash_data():
    if request.method == 'POST':
        ph = PasswordHasher()

        data = request.form.get('data')

        # Validate password.
        if is_password_allowed(data) != True:
            logging.error("hash_data() validation of data failed")
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
            logging.error("create_key() email validation failed")
            return "error: email validation failed"

        # Validate _keypassword.
        if is_password_allowed(key_password) != True:
            logging.error("create_key() key_password validation failed")
            return "error: key_password validation failed"

        # Validate password.
        if is_password_allowed(password) != True:
            logging.error("create_key() password validation failed")
            return "error: password validation failed"

        # Check if password is correct.
        try:
            if ph.verify(current_app.config["PASSWORD_HASH"], password) != True:
                time.sleep(1)
                logging.error("create_key() wrong password")
                return "error: wrong password"
        except VerifyMismatchError:
            time.sleep(1)
            logging.error("create_key() exceptions VerifyMismatchError, wrong password")
            return "error: wrong password"
        time.sleep(1)

        doveadm = current_app.config["DOVEADM_BIN"]

        # Check that doveadm exist.
        if os.path.exists(doveadm) != True:
            logging.error("create_key() doveadm binary location is wrong")
            return "error: doveadm binary location is wrong"

        # Create key with password
        try:
            output = subprocess.run(["/usr/bin/doas",doveadm,"-o","plugin/mail_crypt_private_password="+key_password,"mailbox","cryptokey","generate","-u",email,"-U"], check=True)
            if output.returncode != 0:
                logging.error("create_key() returncode of cmd doveadm is non zero")
                return "error: returncode of cmd doveadm is non zero"
        except subprocess.CalledProcessError as e:
            logging.error("create_key() returncode of cmd doveadm is non zero")
            return "error: returncode of cmd doveadm is non zero"
        except:
            logging.error("create_key() unkown exception running subprocess")
            return "error: unkown exception running subprocess"

        logging.debug("create_key() done")
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
            logging.error("change_password_on_key() email validation failed")
            return "error: email validation failed"

        # Validate current_key_password.
        if is_password_allowed(current_key_password) != True:
            logging.error("change_password_on_key() current_key_password validation failed")
            return "error: current_key_password validation failed"

        # Validate new_key_password.
        if is_password_allowed(new_key_password) != True:
            logging.error("change_password_on_key() new_key_password validation failed")
            return "error: new_key_password validation failed"

        # Validate password.
        if is_password_allowed(password) != True:
            logging.error("change_password_on_key() password validation failed")
            return "error: password validation failed"

        # Check if password is correct.
        try:
            if ph.verify(current_app.config["PASSWORD_HASH"], password) != True:
                time.sleep(1)
                logging.error("change_password_on_key() wrong password")
                return "error: wrong password"
        except:
            time.sleep(1)
            logging.error("change_password_on_key() wrong password")
            return "error: wrong password"
        time.sleep(1)

        doveadm = current_app.config["DOVEADM_BIN"]

        # Check that doveadm exist.
        if os.path.exists(doveadm) != True:
            logging.error("change_password_on_key() doveadm binary location is wrong")
            return "error: doveadm binary location is wrong"

        # Change password on key.
        try:
            output = subprocess.run(["/usr/bin/doas",doveadm,"mailbox","cryptokey","password","-u",email,"-n",new_key_password,"-o",current_key_password], check=True)
            if output.returncode != 0:
                logging.error("change_password_on_key() returncode of cmd doveadm is non zero")
                return "error: returncode of cmd doveadm is non zero"
        except subprocess.CalledProcessError as e:
            logging.error("change_password_on_key() returncode of cmd doveadm is non zero")
            return "error: returncode of cmd doveadm is non zero"
        except:
            logging.error("change_password_on_key() unkown exception running subprocess")
            return "error: unkonwn exception running subprocess"

        logging.debug("change_password_on_key() done")
        return "done"
