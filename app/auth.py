import functools
import random
import flask
from . import utils

from email.message import EmailMessage
import smtplib

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/activate', methods=('GET', 'POST'))
def activate():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'GET': 
            number = request.args['auth'] 
            
            db = get_db()
            attempt = db.execute(
                'SELECT * FROM activationlink where challenge=? and state=? and CURRENT_TIMESTAMP BETWEEN created AND validuntil', (number, utils.U_UNCONFIRMED)
            ).fetchone()

            if attempt is not None:
                db.execute(
                    'UPDATE activationlink SET state = ? WHERE id = ?', (utils.U_CONFIRMED, attempt['id'])
                )
                db.execute(
                    'INSERT INTO user (username, password,salt,email) VALUES (?,?,?,?)', (attempt['username'], attempt['password'], attempt['salt'], attempt['email'])
                )
                db.commit()

        return redirect(url_for('auth.login'))
    except Exception as e:
        print(e)
        return redirect(url_for('auth.login'))


@bp.route('/register', methods=('GET', 'POST'))
def register():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
      
        if request.method == 'POST':    
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            
            db = get_db()
            error = None

            if not username:
                error = 'Username is required.'
                flash(error)
                return render_template('auth/register.html')
            
            if not utils.isUsernameValid(username):
                error = "El nombre de usuario debe ser alfanumérico y adicionar '.','_','-'"
                flash(error)
                return render_template('auth/register.html')

            if not password:
                error = 'La contraseña es requerida.'
                flash(error)
                return render_template('auth/register.html')

            if db.execute('SELECT id FROM user WHERE username = ?', (username,)).fetchone() is not None:
                error = 'El usuario {} ya se encuentra registrado.'.format(username)
                flash(error)
                return render_template('auth/register.html')
            
            if((not email) or (not utils.isEmailValid(email))):
                error =  'El correo electrónico es inválido.'
                flash(error)
                return render_template('auth/register.html')
            
            if db.execute('SELECT id FROM user WHERE email = ?', (email,)).fetchone() is not None:
                error =  'El correo {} ya se encuentra registrado.'.format(email)
                flash(error)
                return render_template('auth/register.html')
            
            if(not utils.isPasswordValid(password)):
                error = 'La contraseña debe tener al menos 8 caracteres, una minúscula, una mayúscula y un número.'
                flash(error)
                return render_template('auth/register.html')

            salt = hex(random.getrandbits(128))[2:]
            hashP = generate_password_hash(password + salt)
            number = hex(random.getrandbits(512))[2:]

            db.execute(
                'INSERT INTO activationlink (challenge, state, username, password,salt,email) VALUES (?,?,?,?,?,?)',
                (number, utils.U_UNCONFIRMED, username, hashP, salt, email)
            )
            db.commit()

            credentials = db.execute(
                'Select user,password from credentials where name=?', (utils.EMAIL_APP,)
            ).fetchone()

            content = 'Hola tripulante, para activar tu cuenta por favor haz click en este enlace ' + flask.url_for('auth.activate', _external=True) + '?auth=' + number
            
            send_email(credentials, receiver=email, subject='Activa tu cuenta', message=content)
            
            flash('Por favor revisa tu correo electrónico para activar tu cuenta')
            return render_template('auth/login.html') 

        return render_template('auth/register.html') 
    except:
        return render_template('auth/register.html')

    
@bp.route('/confirm', methods=('GET', 'POST'))
def confirm():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST': 
            password = request.form['password'] 
            password1 = request.form['password1']
            authid = request.form['authid']

            if not authid:
                flash('Inválido')
                return render_template('auth/forgot.html')

            if not password:
                flash('La contraseña es obligatoria')
                return render_template('auth/change.html', number=authid)

            if not password1:
                flash('Se necesita confirmar la contraseña')
                return render_template('auth/change.html', number=authid)

            if password1 != password:
                flash('Ambos campos deben ser iguales')
                return render_template('auth/change.html', number=authid)

            if not utils.isPasswordValid(password):
                error = 'La contraseña debe tener al menos 8 caracteres, una minúscula, una mayúscula y un número.'
                flash(error)
                return render_template('auth/change.html', number=authid)

            db = get_db()
            attempt = db.execute(
                'SELECT * FROM forgotlink where challenge=? and state=? and CURRENT_TIMESTAMP BETWEEN created AND validuntil', (authid, utils.F_ACTIVE)
            ).fetchone()
            
            if attempt is not None:
                db.execute(
                    'UPDATE forgotlink SET state = ? WHERE id = ?', (utils.F_INACTIVE, attempt['id'])
                )
                salt = hex(random.getrandbits(128))[2:]
                hashP = generate_password_hash(password + salt)   
                db.execute(
                    'UPDATE user SET password = ?, salt=? WHERE id = ?', (hashP, salt, attempt['userid'])
                )
                db.commit()
                return redirect(url_for('auth.login'))
            else:
                flash('Invalid')
                return render_template('auth/forgot.html')

        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')


@bp.route('/change', methods=('GET', 'POST'))
def change():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'GET': 
            number = request.args['auth'] 
            
            db = get_db()
            attempt = db.execute(
                'SELECT * FROM forgotlink where challenge=? and state=? and CURRENT_TIMESTAMP BETWEEN created AND validuntil', (number, utils.F_ACTIVE)
            ).fetchone()
            
            if attempt is not None:
                return render_template('auth/change.html', number=number)
        
        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')


@bp.route('/forgot', methods=('GET', 'POST'))
def forgot():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'POST':
            email = request.form['email']
            
            if ((not email) or (not utils.isEmailValid(email))):
                error = 'Correo inválido'
                flash(error)
                return render_template('auth/forgot.html')

            db = get_db()
            user = db.execute(
                'SELECT * FROM user WHERE email = ?', (email,)
            ).fetchone()

            if user is not None:
                number = hex(random.getrandbits(512))[2:]
                
                db.execute(
                    'UPDATE forgotlink SET state = ? WHERE userid = ?',
                    (utils.F_INACTIVE,user['id'])
                )
                db.execute(
                    'INSERT INTO forgotlink (userid, challenge,state ) VALUES (?,?,?)',
                    (user['id'], number, utils.F_ACTIVE)
                )
                db.commit()
                
                credentials = db.execute(
                    'Select user,password from credentials where name=?',(utils.EMAIL_APP,)
                ).fetchone()
                
                content = 'Hola tripulante, haz click en este enlace para cambiar tu contraseña ' + flask.url_for('auth.change', _external=True) + '?auth=' + number
                
                send_email(credentials, receiver=email, subject='New Password', message=content)
                
                flash('Por favor revisa tu correo electrónico')
            else:
                error = 'El correo no se encuentra registrado'
                flash(error)            

        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            if not username:
                error = 'El campo Usuario es obligatorio'
                flash(error)
                return render_template('auth/login.html')

            if not password:
                error = 'El campo Contraseña es obligatorio'
                flash(error)
                return render_template('auth/login.html')

            db = get_db()
            error = None
            user = db.execute(
                'SELECT * FROM user WHERE username = ?', (username,)
            ).fetchone()
            
            if user is None:
                error = 'Contraseña o usuario incorrecto'
            elif not check_password_hash(user['password'], password + user['salt']):
                error = 'Contraseña o usuario incorrecto'   

            if error is None:
                session.clear()
                session['user_id'] = user['id']
                return redirect(url_for('inbox.show'))

            flash(error)

        return render_template('auth/login.html')
    except:
        return render_template('auth/login.html')
        

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

        
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view


def send_email(credentials, receiver, subject, message):
    # Create Email
    email = EmailMessage()
    email["From"] = credentials['user']
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)

    # Send Email
    smtp = smtplib.SMTP("smtp-mail.outlook.com", port=587)
    smtp.starttls()
    smtp.login(credentials['user'], credentials['password'])
    smtp.sendmail(credentials['user'], receiver, email.as_string())
    smtp.quit()