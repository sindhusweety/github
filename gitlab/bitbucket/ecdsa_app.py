from flask import Blueprint, request
from ecdsa import SigningKey, NIST384p
import base64, codecs
from cryptography.fernet import Fernet

ecdsa_app = Blueprint('ecdsa_app', __name__, url_prefix='/ecdsa_app')
f = Fernet(Fernet.generate_key())

sk = SigningKey.generate(curve=NIST384p)
vk = sk.get_verifying_key()




@ecdsa_app.get('/create_pkey')
def private_key():
    #reverse = bytes.fromhex(sk.to_string().hex()) 
    return {"status":"success", "result":sk.to_string().hex()}

@ecdsa_app.post('/op')
def check_op():
    input = request.get_json()
    operators = ['+', '-', '*', '/', '**', '//', '%']
    finaloutput = {}
    if input['data']['op'] in operators:
        finaloutput['status'] = 'success'
        finaloutput['message'] = 'successfully verified'
        finaloutput['result'] = str(input['data'])
    else:
        finaloutput['status'] = 'failure'
        finaloutput['message'] = 'invalid operator'
    return finaloutput

@ecdsa_app.post('/verify_signature')
def signature_verify():

    input = request.get_json()
    token = f.encrypt(str(input['data']).encode())
    #reverse_signature = bytes.fromhex(input["signature"])
    signature_ = sk.sign(token)
    finaloutput = {}
    try:
        if (vk.verify(signature_, token)):
            finaloutput['status'] = 'success'
            finaloutput['message'] = 'successfully verified'
    except:
        finaloutput['status'] = 'failure'
        finaloutput['message'] = 'signature is invalid'

    return finaloutput


@ecdsa_app.post('/verify')
def verify_fun():
    data = request.get_json()
    output = check_operator_verify(data)
    finaloutput ={}
    if output:
        finaloutput['status'] = 'success'
        finaloutput['message'] = 'successfully verified'
    else:
        finaloutput['status'] = 'failure'
        finaloutput['message'] = 'invalid operator or signature is invalid'
    return finaloutput

def check_operator_verify(input):
    try:
        operators = ['+', '-', '*', '/', '**', '//', '%']
        if input['data']['op'] in operators:
            token = f.encrypt(str(input['data']).encode())
            reverse_signature = bytes.fromhex(input["signature"])
            return (vk.verify(reverse_signature, token))
    except:
        pass

        