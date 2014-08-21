import framework

import webapp2
import uberapi

import json
import os


app = framework.WSGIApplication()
uber = uberapi.UberAPI(client_id=os.environ['UBER_CLIENT_ID'],
                       client_secret=os.environ['UBER_CLIENT_SECRET'],
                       redirect_uri=os.environ['UBER_REDIRECT_URI'])
                       # You have to enable billing for App Engine in order
                       # to use the SSL module. It's dumb.
                       #ssl_ca_certs='/etc/ca-certificates.crt')


@app.route('/oauth/login')
def oauth_login(request, *args, **kwargs):
    url = uber.get_authorize_url()
    return webapp2.redirect(url)


@app.route('/oauth/callback')
def oauth_callback(request, *args, **kwargs):
    code = request.get('code', None)
    if code is None:
        return webapp2.Response('Missing "code" query parameter', status=400)

    token = uber.get_access_token(code)

    response = webapp2.redirect('/')
    response.set_cookie('access_token', token['access_token'],
                        max_age=token['expires_in'], secure=True)
    response.set_cookie('refresh_token', token['refresh_token'],
                        secure=True)
    return response


@app.route('/oauth/logout')
def oauth_logout(request, *args, **kwargs):
    response = webapp2.redirect('/')
    response.set_cookie('access_token', '', max_age=0, secure=True)
    response.set_cookie('refresh_token', '', max_age=0, secure=True)
    return response


@app.route('/')
def index(request, *args, **kwargs):
    access_token = request.cookies.get('access_token', None)
    if not access_token:
        return webapp2.redirect('/oauth/login')

    resp = uber.request('GET', '/v1/me', token=access_token)
    response = webapp2.Response(json.dumps(resp, indent=2))
    response.headers['Content-Type'] = 'text/plain'
    return response
