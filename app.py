# THESE TWO LINES MUST BE AT THE ABSOLUTE TOP
from gevent import monkey
monkey.patch_all()

import os
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'fallback-dev-key-do-not-use-in-prod')

socketio = SocketIO(app, max_http_buffer_size=10000000, cors_allowed_origins="*")

connected_users = {}

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    if len(connected_users) >= 3:
        return False  
    
    connected_users[request.sid] = True
    emit('system_message', {'msg': f'Users in room: {len(connected_users)}/3'}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in connected_users:
        del connected_users[request.sid]
    emit('system_message', {'msg': f'Users in room: {len(connected_users)}/3'}, broadcast=True)

@socketio.on('announce_public_key')
def handle_announce_pubkey(data):
    data['sender_sid'] = request.sid
    emit('receive_public_key', data, broadcast=True, include_self=False)

@socketio.on('reply_public_key')
def handle_reply_pubkey(data):
    data['sender_sid'] = request.sid
    emit('receive_public_key', data, to=data['target_sid'])

@socketio.on('send_encrypted_payload')
def handle_payload(data):
    data['sender_sid'] = request.sid
    emit('receive_encrypted_payload', data, broadcast=True, include_self=False)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
