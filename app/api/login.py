from bottle import (
    get,
    post,
    redirect,
    request,
    response,
    jinja2_template as template,
)

from app.models.user import create_user, get_user
from app.models.breaches import get_breaches
from app.models.session import (
    delete_session,
    create_session,
    get_session_by_username,
    logged_in,
)

from app.util.hash import (
        hash_pbkdf2,
        hash_sha256,
 )

def creds_in_breaches(db, username, password):
    plaintext_breaches, hashed_breaches, salted_breaches = get_breaches(db, username)
    for user in plaintext_breaches:
        if user.username == username and user.password == password:
            #print('found in plaintext breaches')
            return True
    
    for user in hashed_breaches:
        hash_pswd = hash_sha256(password)
        if user.username == username and user.hashed_password == hash_pswd:
            #print('found in hashed breaches')
            return True
    
    for user in salted_breaches:
        salt = user.salt
        salted_hash = hash_pbkdf2(password, salt)
        if user.username == username and user.salted_password == salted_hash:
            #print('found in salted breaches')
            return True

    return False

@get('/login')
def login():
    return template('login')

@post('/login')
def do_login(db):
    username = request.forms.get('username')
    password = request.forms.get('password')
    error = None
    user = get_user(db, username)
    print(user)
    if (request.forms.get("login")):
        if user is None:
            response.status = 401
            error = "{} is not registered.".format(username)
        elif user.password != password:
            response.status = 401
            error = "Wrong password for {}.".format(username)
        else:
            pass  # Successful login
    elif (request.forms.get("register")):
        if user is not None:
            response.status = 401
            if creds_in_breaches(db, username, password):
                error = "username: {} and password found in breaches!".format(username)
            else:
                error = "{} is already taken.".format(username)
        else:
            create_user(db, username, password)
    else:
        response.status = 400
        error = "Submission error."
    if error is None:  # Perform login
        existing_session = get_session_by_username(db, username)
        if existing_session is not None:
            delete_session(db, existing_session)
        session = create_session(db, username)
        response.set_cookie("session", str(session.get_id()))
        return redirect("/{}".format(username))
    return template("login", error=error)

@post('/logout')
@logged_in
def do_logout(db, session):
    delete_session(db, session)
    response.delete_cookie("session")
    return redirect("/login")


