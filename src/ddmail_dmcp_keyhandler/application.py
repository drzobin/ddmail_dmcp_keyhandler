from flask import Blueprint, current_app, request
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import os
import time
import subprocess
import logging

from dmcp_keyhandler.validators import is_domain_allowed, is_password_allowed, is_email_allowed

bp = Blueprint("application", __name__, url_prefix="/")

@bp.route("/create_key", methods=["POST"])
def create_key():
    if request.method == 'POST':
        ph = PasswordHasher()

        email = request.form.get('email')
        key_password = request.form.get('key_password')
        password = request.form.get('password')

        # Validate email.
        if is_email_allowed(email) != True:
            current_app.logger.error("email validation failed")
            return "error: email validation failed"

        # Validate _keypassword.
        if is_password_allowed(key_password) != True:
            current_app.logger.error("key_password validation failed")
            return "error: key_password validation failed"

        # Validate password.
        if is_password_allowed(password) != True:
            current_app.logger.error("password validation failed")
            return "error: password validation failed"

        # Check if password is correct.
        try:
            if ph.verify(current_app.config["PASSWORD_HASH"], password) != True:
                time.sleep(1)
                current_app.logger.error("wrong password")
                return "error: wrong password"
        except VerifyMismatchError:
            time.sleep(1)
            current_app.logger.error("exceptions VerifyMismatchError, wrong password")
            return "error: wrong password"
        time.sleep(1)

        doveadm = current_app.config["DOVEADM_BIN"]

        # Check that doveadm exist.
        if os.path.exists(doveadm) != True:
            current_app.logger.error("doveadm binary location is wrong")
            return "error: doveadm binary location is wrong"

        # Create key with password
        try:
            output = subprocess.run(["/usr/bin/doas",doveadm,"-o","plugin/mail_crypt_private_password="+key_password,"mailbox","cryptokey","generate","-u",email,"-U"], check=True)
            if output.returncode != 0:
                current_app.logger.error("returncode of cmd doveadm is non zero")
                return "error: returncode of cmd doveadm is non zero"
        except subprocess.CalledProcessError as e:
            current_app.logger.error("returncode of cmd doveadm is non zero")
            return "error: returncode of cmd doveadm is non zero"
        except:
            current_app.logger.error("unkown exception running subprocess")
            return "error: unkown exception running subprocess"

        current_app.logger.debug("done")
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
            current_app.logger.error("email validation failed")
            return "error: email validation failed"

        # Validate current_key_password.
        if is_password_allowed(current_key_password) != True:
            current_app.logger.error("current_key_password validation failed")
            return "error: current_key_password validation failed"

        # Validate new_key_password.
        if is_password_allowed(new_key_password) != True:
            current_app.logger.error("new_key_password validation failed")
            return "error: new_key_password validation failed"

        # Validate password.
        if is_password_allowed(password) != True:
            current_app.logger.error("password validation failed")
            return "error: password validation failed"

        # Check if password is correct.
        try:
            if ph.verify(current_app.config["PASSWORD_HASH"], password) != True:
                time.sleep(1)
                current_app.logger.error("wrong password")
                return "error: wrong password"
        except:
            time.sleep(1)
            current_app.logger.error("wrong password")
            return "error: wrong password"
        time.sleep(1)

        doveadm = current_app.config["DOVEADM_BIN"]

        # Check that doveadm exist.
        if os.path.exists(doveadm) != True:
            current_app.logger.error("doveadm binary location is wrong")
            return "error: doveadm binary location is wrong"

        # Change password on key.
        try:
            output = subprocess.run(["/usr/bin/doas",doveadm,"mailbox","cryptokey","password","-u",email,"-n",new_key_password,"-o",current_key_password], check=True)
            if output.returncode != 0:
                current_app.logger.error("returncode of cmd doveadm is non zero")
                return "error: returncode of cmd doveadm is non zero"
        except subprocess.CalledProcessError as e:
            current_app.logger.error("returncode of cmd doveadm is non zero")
            return "error: returncode of cmd doveadm is non zero"
        except:
            current_app.logger..error("unkown exception running subprocess")
            return "error: unkonwn exception running subprocess"

        current_app.logger.debug("done")
        return "done"
