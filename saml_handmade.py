from flask import Flask
from gen_saml_response import *

app = Flask(__name__)

@app.route("/openid-configuration")
def metadata():
    f = open("metadata.txt", "r")
    return f.read()

@app.route("/sso/saml")
def authorize():
    f = open("myjs.txt", "r")
    content = f.read()
    response_body = content.replace('%saml_response%', generate_saml_response())
    return response_body