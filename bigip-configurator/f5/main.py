# main.py

from flask import Flask, render_template, request, redirect, url_for, session, g
from step1 import *
from flask import jsonify

app = Flask(__name__, static_url_path='/static')
app.secret_key = 'dkjasd9876asduyasgdas67dtaiusdads'


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        session['username'] = username
        session['password'] = password

        # Use bigip_login function to authenticate the user
        bigip_token, formatted_cookies = bigip_login(username, password)
        if bigip_token and formatted_cookies:
            # Store only necessary information in the session
            session['authenticated'] = True
            session['bigip_token'] = bigip_token
            session['formatted_cookies'] = formatted_cookies

            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'reason': 'Invalid username or password'})


@app.route('/vs_already_exist', methods=['POST'])
def vs_already_exist():
    virtual_address = request.form['virtualAddress']
    service_name = request.form['serviceName']
    vs_exist = check_if_vs_exist(virtual_address, service_name, session['username'], session['password'])
    if vs_exist:
        return jsonify({'success': False, 'reason': 'The virtual address or service name already exists'})
    else:
        return jsonify({'success': True, 'reason': 'Good'})


@app.route('/submit_form', methods=['POST'])
def submit_form():
    if request.method == 'POST':
        service_name = request.form['serviceName']
        virtual_address = request.form['virtualAddress']
        audience = request.form['audience']
        backend_address = request.form['backendAddress']
        create_audience(audience, session['username'], session['password'])
        node_creator(request.form['backendAddress'], session['username'], session['password'])
        pool_creator(service_name, session['username'], session['password'])
        pool_members_assignment(service_name, request.form['backendAddress'], session['bigip_token'], session['username'], session['password'])
        create_api_protection_profile(service_name, backend_address, session['bigip_token'])
        create_pre_request_policy(service_name, session['bigip_token'], session['formatted_cookies'])
        vs_creator(service_name, virtual_address, session['username'], session['password'])

        success_message = {
            'service_name': service_name,
            'virtual_address': virtual_address,
            'audience': audience,
            'backend_address': backend_address
        }

        return render_template('success.html', success_message=success_message)


if __name__ == '__main__':
    app.run(debug=True, port=8080, host='0.0.0.0')

