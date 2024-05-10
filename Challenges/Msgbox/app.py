import datetime
import re
import uuid
from functools import wraps
import jwt
import random
import string

import robot
import os
from flask import Flask, request, jsonify, make_response, redirect, render_template
from selenium import webdriver

# flask
app = Flask(__name__)

# I wouldn't set expiry since it's unnecessary
jwt_key = os.urandom(24)

# Gokurou-sama deshita, Memori-kun
users = {}
db = {}


class Msg:
    def __init__(self, header, sender, listener, content):
        self.uid = uuid.uuid4()
        self.header = header
        self.sender = sender
        self.listener = listener
        self.content = content
        self.creation = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def __eq__(self, other):
        if str(self.uid) == str(other):
            return True
        else:
            return False

    def __str__(self) -> str:
        return str(self.uid)


def rand_gen(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


def register(username, password):
    if '' in [username, password]:
        return False, 'blank username or password'
    if username in users:
        return False, 'username already used'
    if len(password) < 8:
        return False, 'password must be at least 8 characters long'
    if not re.match(r"^[0-9a-zA-Z]{8,}$", password):
        return False, 'only letters and numbers allowed in password'
    users[username] = password
    db[username] = {
        'outbox': [],
        'inbox': []
    }
    return True, f'Hello, {username}'


def login(username, password):
    if '' in [username, password]:
        return False, 'blank username or password'
    if username in users and users[username] == password:
        return True, f'{username}, Login Successfully'
    return False, 'invalid username or password'


def grant_jwt(username):
    return jwt.encode(payload={'username': username, 'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')},
                      key=jwt_key,
                      algorithm='HS256')


def read_jwt(token):
    try:
        payload = jwt.decode(token, jwt_key, algorithms='HS256')
        return payload
    except Exception as e:
        raise e


def require_jwt(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        jwt_token = request.cookies.get('auth')
        if not jwt_token:
            return render_template('login_requirement.html')

        try:
            payload = read_jwt(jwt_token)
        except jwt.InvalidTokenError:
            return render_template('login_requirement.html')

        # 将解码后的 payload 传递给被装饰的函数
        return f(payload, *args, **kwargs)

    return decorated_function


def check_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        jwt_token = request.cookies.get('auth')
        if not jwt_token:
            return f(logged=False, *args, **kwargs)
        try:
            payload = read_jwt(jwt_token)
        except jwt.InvalidTokenError:
            return f(logged=False, *args, **kwargs)

        # 将解码后的 payload 传递给被装饰的函数
        return f(logged=True, *args, **kwargs)

    return decorated_function


# index
@app.route("/", methods=['GET'])
@check_login
def req_index(logged):
    if logged:
        return redirect("/inbox")
    else:
        return redirect("/login")


# Logout
@app.route("/logout", methods=['GET'])
@check_login
def req_logout(logged):
    if not logged:
        return redirect("/login")
    resp = make_response(redirect("/"))
    resp.delete_cookie("auth")
    return resp


# Register
@app.route("/register", methods=['GET', 'POST'])
@check_login
def req_register(logged):
    if logged:
        return redirect("/inbox")
    if request.method == 'GET':
        return render_template('register.html')
    else:
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        print(f'register request with user: {username}, pass: {password}')
        flag, msg = register(username, password)

        if flag:
            print(f'new user: {username}, pass: {password}')
            resp = make_response({'success': flag, 'redirect': '/inbox'})
            resp.set_cookie('auth', grant_jwt(username), httponly=True)
            return resp
        return jsonify({'success': flag, 'msg': msg})


# Login
@app.route("/login", methods=['GET', 'POST'])
@check_login
def req_login(logged):
    if logged:
        return redirect("/inbox")
    if request.method == 'GET':
        return render_template('login.html')
    else:
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        print(f'login request with user: {username}, pass: {password}')
        flag, msg = login(username, password)

        if flag:
            print(f'login with user: {username}, pass: {password}')
            resp = make_response(jsonify({'success': flag, 'redirect': '/inbox'}))
            resp.set_cookie('auth', grant_jwt(username), httponly=True)
            return resp
        return jsonify({'success': flag, 'msg': msg})


# Fetch Inbox
@app.route("/inbox", methods=['GET'])
@require_jwt
def req_inbox(payload):
    msg_list = db[payload['username']]['inbox']
    return render_template('inbox.html', messages=msg_list)


# Fetch Outbox
@app.route("/outbox", methods=['GET'])
@require_jwt
def req_outbox(payload):
    msg_list = db[payload['username']]['outbox']
    return render_template('outbox.html', messages=msg_list)


# Send Msg
@app.route("/send", methods=['GET', 'POST'])
@require_jwt
def req_send(payload):
    if request.method == 'GET':
        return render_template('send.html')
    sender = payload['username']
    header = request.form.get('header', None)
    listener = request.form.get('listener', None)
    content = request.form.get('content', None)
    if None in [sender, header, listener, content]:
        return 'missing complete information!'
    if listener not in users:
        return 'receiving user of the msg not exist'
    msg = Msg(header, sender, listener, content)
    db[listener]['inbox'].insert(0, msg)
    db[sender]['outbox'].insert(0, msg)
    return render_template('send_success.html')


# Read Msg
@app.route("/read", methods=['GET'])
@require_jwt
def req_read(payload):
    uid = request.args.get('id')
    if not uid:
        return redirect("/inbox")
    for msg in db[payload['username']]['inbox']:
        if msg == uid:
            return render_template('read.html', message=msg, nonce=rand_gen(16))
    for msg in db[payload['username']]['outbox']:
        if msg == uid:
            return render_template('read.html', message=msg, nonce=rand_gen(16))
    return jsonify({'msg': 'not found'})


# Checker
@app.route("/report", methods=['GET'])
def req_check():
    options = set_chrome_options()
    print("bot: init driver")
    driver = webdriver.Remote(command_executor='http://chrome:4444/wd/hub', options=options)
    print("bot: driver ready")
    print("bot: preparing checker")
    checker = robot.AdminBot(os.getenv('FLAG', 'flag{testflag}'), admin_user, admin_pass, 'http://web:5000/', driver)
    res = checker.check()
    print("bot: check complete, admin inbox cleared")
    db['admin'] = {
        'outbox': [],
        'inbox': []
    }
    driver.quit()
    return res


# admin info
admin_user = 'admin'
admin_pass = rand_gen(24)
print("Admin created with password " + admin_pass)
register(admin_user, admin_pass)


def set_chrome_options() -> webdriver.ChromeOptions:
    """Sets chrome options for Selenium.
    Chrome options for headless browser is enabled.
    """
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument('--ignore-certificate-errors')
    return chrome_options

app.run(host='0.0.0.0')
