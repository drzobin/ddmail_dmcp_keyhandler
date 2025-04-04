from flask import current_app
import pytest
import os

def test_create_key_illigal_char_password(client):
    response_hash_data_post = client.post("/create_key", data={"password":".password","key_password":"aDfrdf43DFR432dFtrfde43E","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: password validation failed" in response_hash_data_post.data

def test_create_key_illigal_char_key_password(client,password):
    response_hash_data_post = client.post("/create_key", data={"password":password,"key_password":"p<assword","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: key_password validation failed" in response_hash_data_post.data

def test_create_key_illigal_char_email(client):
    response_hash_data_post = client.post("/create_key", data={"password":"password","key_password":"password","email":"te\"st@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: email validation failed" in response_hash_data_post.data

def test_create_key_wrong_password(client):
    response_hash_data_post = client.post("/change_password_on_key", data={"password":"adFrd34fd34rFDert4edFTRE","current_key_password":"sd34fgFD34fdERF43edSDFTR","new_key_password":"dDFrdswD34fdSed3fdRtfrtf","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: wrong password" in response_hash_data_post.data

def test_change_password_on_key_illigal_char_password(client):
    response_hash_data_post = client.post("/change_password_on_key", data={"password":"aSdfrGf345fdrtGFrdFR54.2","current_key_password":"sd34fgFD34fdERF43edSDFTR","new_key_password":"dDFrdswD34fdSed3fdRtfrtf","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: password validation failed" in response_hash_data_post.data

def test_change_password_on_key_illigal_char_current_key_password(client):
    response_hash_data_post = client.post("/change_password_on_key", data={"password":"password","current_key_password":"p<assword","new_key_password":"password","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: current_key_password validation failed" in response_hash_data_post.data

def test_change_password_on_key_illigal_char_new_key_password(client, password):
    response_hash_data_post = client.post("/change_password_on_key", data={"password":password,"current_key_password":"aSdf3fde34fDFR345fdeFDRT","new_key_password":"pas%sword","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: new_key_password validation failed" in response_hash_data_post.data

def test_change_password_on_key_illigal_char_email(client):
    response_hash_data_post = client.post("/change_password_on_key", data={"password":"password","current_key_password":"password","new_key_password":"password","email":"test@te--st.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: email validation failed" in response_hash_data_post.data

def test_change_password_on_key_wrong_password(client):
    response_hash_data_post = client.post("/change_password_on_key", data={"password":"A3D4fEf3D3F45gFds23F4gfR","current_key_password":"aDfD3fdFd3rFDs345FdsFrdf","new_key_password":"aDfrGf34fdFgt54fdFgfrdfT","email":"test@test.se"})
    assert response_hash_data_post.status_code == 200
    assert b"error: wrong password" in response_hash_data_post.data
