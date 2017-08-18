import bson.json_util
import mongo_util
import os
import logging
import re
from models import User
from pymongo import MongoClient
from flask import Flask, request, redirect, url_for, abort
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, fresh_login_required
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config.update(dict(
  PREFERRED_URL_SCHEME = 'https'
))
login_manager = LoginManager()
login_manager.init_app(app)
app.logger.setLevel(logging.INFO)

@login_manager.user_loader
def user_loader(user_id):
    with mongo_util.mongo() as db:
        user = db.users.find_one({'username': user_id})
        if user:
            new_user = User(user['username'], user['password'])
            return new_user
        else:
            return None

@app.route('/')
def hello():
    return app.send_static_file('index.html')

@app.route('/401')
def forbidden():
    return app.send_static_file('index.html')

@app.route('/getUserStats')
@login_required
def get_user_stats():
    logged_in_user = mongo_util.get_user(current_user)
    if logged_in_user:
        return bson.json_util.dumps(logged_in_user)
    else:
        return bson.json_util.dumps({'error': 'Could not find logged in user'}), 400

@app.route('/setUserStats')
@login_required
def set_user_stats():
    running = request.args.get('running', 0.0)
    biking = request.args.get('biking', 0.0)
    swimming = request.args.get('swimming', 0.0)
    percent_complete = mongo_util.set_user_stats(current_user.username, running, biking, swimming)
    if percent_complete >= 0:
        return bson.json_util.dumps({'running': running, 'biking': biking, 'swimming': swimming, 'percent_complete': percent_complete})
    else:
        return bson.json_util.dumps({'error': 'Could not update stats'}), 400

@app.route('/updateUserStats')
@login_required
def update_user_stats():
    run = request.args.get('running', 0.0)
    bike = request.args.get('biking', 0.0)
    swim = request.args.get('swimming', 0.0)
    try:
        running, biking, swimming, percent_complete = mongo_util.update_user_stats(current_user, running=run, biking=bike, swimming=swim)
        return bson.json_util.dumps({'swimming': swimming, 'running': running, 'biking': biking, 'percent_complete': percent_complete})
    except Exception as e:
        return bson.json_util.dumps({'error': str(e)}), 400

@app.route('/getLeaderBoard')
def get_leader_board():
    leader = list(mongo_util.get_leaderboard())
    for i in leader:
        del i['password']
        del i['_id']
    return bson.json_util.dumps(sorted(leader, key=lambda k: k['percent_complete'], reverse=True))

@app.route('/doLogin', methods=['GET', 'POST'])
def do_login():
    if request.method == 'POST':
        with mongo_util.mongo() as db:
            body = request.get_json()

            # Make sure username and password are in the request
            if 'username' not in body or 'password' not in body:
                return bson.json_util.dumps({'status': 500, 'error': 'Bad request'}), 500

            # Generate secure hash
            password = generate_password_hash(body['password'])

            # Make sure the user does not already exist
            regx_search = re.compile(body['username'], re.IGNORECASE)
            user = db.users.find_one({'username': regx_search})
            if not user:
                user = db.users.insert_one({'username': body['username'], 'password': password, 'firstName': body.get('firstName', ''), 'lastName': body.get('lastName', ''), 'running': 0.0, 'biking': 0.0, 'swimming': 0.0, 'percent_complete': 0.0})
                if user.inserted_id:
                    new_user = User(body['username'], password)
                    new_user.authenticated = True
                    login_user(new_user)
                    return bson.json_util.dumps({'status': 200, 'response': 'Successfully created a new account'})
                else:
                    return bson.json_util.dumps({'status': 500, 'error': 'Could not create new account'}), 500
            else:
                return bson.json_util.dumps({'status': 400, 'error': 'Username already exists'}), 400
    elif request.method == 'GET':
        with mongo_util.mongo() as db:
            username = request.args.get('username', '')
            password = request.args.get('password', '')
            remember = request.args.get('remember', False)
            app.logger.info("Remember me: %s" % remember)
            if username == '' or password == '':
                return bson.json_util.dumps({'status': 200, 'response': 'Bad request'})

            # Verify credentials
            regx_search = re.compile(username, re.IGNORECASE)
            user = db.users.find_one({'username': regx_search})
            if user:
                # User already exists so log them in
                new_user = User(user['username'], user['password'])
                if check_password_hash(user['password'], password):
                    if not login_user(new_user, remember=remember):
                        return bson.json_util.dumps({'status': 400, 'error': 'Login failed'}), 400
                    return bson.json_util.dumps({'status': 200, 'response': 'Successfully logged in'}), 200
                else:
                    return bson.json_util.dumps({'status': 400, 'error': 'Incorrect username or password'}), 400
            else:
                return bson.json_util.dumps({'status': 400, 'error': 'Incorrect username or password'}), 400


@app.route('/isLoggedIn')
def is_logged_in():
    if current_user.is_authenticated:
        return bson.json_util.dumps({'isLoggedIn': True})
    else:
        return bson.json_util.dumps({'isLoggedIn': False})

@app.route("/doLogout")
@login_required
def do_logout():
    logout_user()
    return bson.json_util.dumps({'response': 'Successfully logged out'});

@app.route("/deleteProfile")
@fresh_login_required
def delete_profile():
    with mongo_util.mongo() as db:
        result = db.users.delete_one({'username': current_user.username})
        if result.deleted_count == 1:
            app.logger.info("Deleting %s" % current_user.username)
            return bson.json_util.dumps({'response': 'Successfully deleted profile'})
        else:
            return bson.json_util.dumps({'error': 'Profile could not be deleted'}), 400

@app.route('/<path:the_path>')
def all_other_routes(the_path):
    return app.send_static_file('index.html')

if __name__ == '__main__':
    app.run()
