# Example for integrating 3botlogin into python

from flask import Flask, redirect, request, abort, send_from_directory
import flask
import nacl
import nacl
import nacl.secret
import nacl.signing
import nacl.utils
import nacl.encoding
from nacl.public import PrivateKey, Box
import random
import string
import base64
import urllib.parse
from urllib.request import urlopen
import json
import requests
import jwt
import base64
import os

# pip3 install pynacl flask requests pyjwt
app = Flask(__name__)

# These keys are generated but should be stored on the disc as they should not change everytime the program starts
sk = PrivateKey.generate()
pk = sk.public_key

pkb64 = sk.public_key.encode(
    encoder=nacl.encoding.Base64Encoder).decode("utf-8")

filebrowserUrl = os.environ['FILEBROWSERURL']
filebrowserFolder = os.environ['FILEBROWSERROOT']
filebrowserSecretKey = os.environ['FILEBROWSERKEY']

filebrowserJwt = jwt.encode({
    'user': {
        'id': 1,
        'locale': 'en',
        'viewMode': 'mosaic',
        'perm': {
            'admin': True,
            'execute': True,
            'create': True,
            'rename': True,
            'modify': True,
            'delete': True,
            'share': True,
            'download': True
        },
        'commands': [],
        'lockPassword': False
    },
    'exp': 1760171877,
    'iat': 1560164677,
    'iss': 'File Browser'
}, base64.b64decode(filebrowserSecretKey), algorithm='HS256')




headers = {"x-auth": filebrowserJwt}


def getJwtForUser(username):
    userId = getUser(username)
    userJwt = jwt.encode({
        'user': {
            'id': userId,
            'locale': 'en',
            'viewMode': 'mosaic',
            'perm': {
                'admin': False,
                'execute': True,
                'create': True,
                'rename': True,
                'modify': True,
                'delete': True,
                'share': True,
                'download': True
            },
            'commands': [],
            'lockPassword': False
        },
        'exp': 1760171877,
        'iat': 1560164677,
        'iss': 'File Browser'
    }, base64.b64decode(filebrowserSecretKey), algorithm='HS256')
    return userJwt.decode('utf-8')


def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


@app.route('/users/<user>')
def getUser(user):
    usersEndpoint = "{}api/users".format(filebrowserUrl)
    response = requests.get(url=usersEndpoint, headers=headers)
    print(response.content)
    users = json.loads(response.content.decode("utf-8"))
    for existingUser in users:
        if existingUser['username'] == user:
            return existingUser['id']
    return 0


@app.route('/createuser')
def createUser(doublename):
    usersEndpoint = "{}api/users".format(filebrowserUrl)
    doublename = "jdelrue.3bot"

    createUser = {
        "what": "user",
        "which": [

        ],
        "data": {
            "scope": doublename,
            "locale": "en",
            "viewMode": "mosaic",
            "sorting": {
                "by": "",
                "asc": False
            },
            "perm": {
                "admin": False,
                "execute": True,
                "create": True,
                "rename": True,
                "modify": True,
                "delete": True,
                "share": True,
                "download": True
            },
            "commands": [

            ],
            "username": doublename,
            "passsword": "",
            "rules": [

            ],
            "lockPassword": True,
            "id": 0,
            "password": randomString(25)
        }
    }

    params = createUser
    jsonparams = json.dumps(params)

    r = requests.post(url=usersEndpoint, data=jsonparams, headers=headers)

    return r.status_code == 201


@app.route('/')
def hello():
    state = randomString()
    res = flask.make_response(redirect(
        'https://login.threefold.me/?state={}&scope=user:email&appid=pythoniseasy&publickey={}&redirecturl=http://localhost:8082/callback'.format(state, urllib.parse.quote_plus(pkb64))))
    res.set_cookie("state", value=state)
    return res


@app.route('/callback')
def callback():
    signedhash = request.args.get('signedhash')
    username = request.args.get('username')
    userResponse = urlopen(
        "https://login.threefold.me/api/users/{}".format(username))

    username = request.args.get('username')
    data = json.loads(userResponse.read())
    userPk = data['publicKey']

    verify_key = nacl.signing.VerifyKey(userPk,
                                        encoder=nacl.encoding.Base64Encoder)

    try:
        verify_key.verify(base64.b64decode(signedhash))
    except:
        print("User signed hash not ok!")
        return abort(400)

    print("does user exists? {} ".format(getUser(username)))
    if getUser(username) == 0:
        print("!!create user!!")
        createUser(username)
        print("creating {}/{}".format(filebrowserFolder, username))
        os.mkdir("{}/{}".format(filebrowserFolder, username))

    res = flask.make_response(redirect('{}login?auth={}'.format(filebrowserUrl,getJwtForUser(username))))
    return res

# @app.route('/files/<filename>')
@app.route('/uploads/<path:filename>')
def getfile(filename):
    print(filename)
    print("/home/code/projects/{}".format(filename))

    return send_from_directory("/home/code/projects", filename)

# https://kite.com/python/docs/flask.send_from_directory


@app.route('/docs')
def opendocs():
    f = open("docs.html", "r")
    contents = f.read()
    return contents


if __name__ == '__main__':
    app.run("0.0.0.0", 8082)

