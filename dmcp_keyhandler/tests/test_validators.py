from flask import current_app
from dmcp_keyhandler.validators import is_email_allowed, is_domain_allowed, is_password_allowed
import pytest
import os

def test_is_password_allowed():
    assert is_password_allowed("aA8/+=") == True
    assert is_password_allowed("aA8/+=\\") == False
