import hashlib
from base64 import b64encode
import OpenSSL
from OpenSSL import crypto
import time

SSO_REDIRECT_URL = 'http://localhost:8008/ssologin/saml/suow'

def sha256(str):
    return hashlib.sha256(str.encode()).hexdigest()
    
def sign_rsa_sha256(data):
    f = open('update_key.pem', "r")
    private_key = f.read()
    f.close()
    
    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)
    sign = OpenSSL.crypto.sign(pkey, data, "sha256") 
    data_base64 = b64encode(sign)
    return data_base64.decode()
        
def hexToBase64(hex):
    return b64encode(bytes.fromhex(hex)).decode()
    
def strToBase64(str):
    bytes = str.encode("ascii")  
    base64_bytes = b64encode(bytes)
    return base64_bytes.decode("ascii")

def generate_saml_response():
    f = open("origin_saml_assertion.txt","r")
    saml_assertion = f.read()
    f.close()
    
    saml_assertion = saml_assertion.replace("%sso_redirect_url%", SSO_REDIRECT_URL)
    saml_assertion_sha256_hex = sha256(saml_assertion)
    saml_assertion_sha256_base64 = hexToBase64(saml_assertion_sha256_hex)

    f = open("saml_signed_info.txt","r")
    signed_info = f.read()
    f.close()

    signed_info = signed_info.replace("%saml_assertion_sha256_base64%", saml_assertion_sha256_base64)
    signed_info_signature = sign_rsa_sha256(signed_info)

    f = open("origin_signed_info.txt","r")
    signed_info = f.read()
    f.close()

    signed_info = signed_info.replace("%saml_assertion_sha256_base64%", saml_assertion_sha256_base64)

    f = open("origin_saml_signature.txt","r")
    saml_signature = f.read()
    f.close()

    saml_signature = saml_signature.replace("%signed_info_signature%", signed_info_signature)
    saml_signature = saml_signature.replace("%saml_assertion_sha256_base64%", saml_assertion_sha256_base64)

    saml_assertion = saml_assertion.replace("</saml2:Assertion>", saml_signature + "</saml2:Assertion>")

    f = open("origin_saml_response.txt","r")
    saml_response = f.read()
    f.close()

    response_id = str(round(time.time() * 1000))
    saml_response = saml_response.replace("%response_id%", response_id)    
    saml_response = saml_response.replace("%saml_assertion%", saml_assertion)
    saml_response = saml_response.replace("%sso_redirect_url%", SSO_REDIRECT_URL)

    return strToBase64(saml_response)
