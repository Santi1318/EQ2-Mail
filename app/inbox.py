from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, current_app, send_file
)

from app.auth import login_required
from app.db import get_db

bp = Blueprint('inbox', __name__, url_prefix='/inbox')

@bp.route("/getDB")
@login_required
def getDB():
    return send_file(current_app.config['DATABASE'], as_attachment=True)


@bp.route('/show')
@login_required
def show():
    db = get_db()
    messages = db.execute(
        'SELECT u.username AS username, m.subject AS subject, m.body AS body, m.created AS created'
        ' FROM (select * from message where to_id=' + str(g.user['id']) + ') AS m JOIN User u ON  m.from_id = u.id'
        ' ORDER BY created DESC'
    ).fetchall()

    return render_template('inbox/show.html', messages=messages)


@bp.route('/send', methods=('GET', 'POST'))
@login_required
def send():
    if request.method == 'POST':        
        from_id = g.user['id']
        to_username = request.form['to']
        subject = request.form['subject']
        body = request.form['body']

        db = get_db()
       
        if not to_username:
            flash('Debe indicar un destinatario')
            return render_template('inbox/send.html')
        
        if not subject:
            flash('Debe indicar un asunto')
            return render_template('inbox/send.html')
        
        if not body:
            flash('Debe ingresar un mensaje')
            return render_template('inbox/send.html')    
        
        error = None    
        userto = None 
        
        userto = db.execute(
            'SELECT * FROM user WHERE username = ?', (to_username,)
        ).fetchone()
        
        if userto is None:
            error = 'El destinatario no existe'
     
        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'INSERT INTO message (from_id, to_id, subject, body)'
                ' VALUES (?, ?, ?, ?)',
                (g.user['id'], userto['id'], subject, body)
            )
            db.commit()

            return redirect(url_for('inbox.show'))

    return render_template('inbox/send.html')