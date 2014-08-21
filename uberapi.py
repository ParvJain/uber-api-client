'''
Uber API client library

Detailed documentation of Uber's API and the available endpoints is available
at https://developer.uber.com/

Authorization of Uber users is done by directing the user's browser to Uber's
authorize endpoint, which will prompt them to login and allow your application
access to the user's data. Once the user has approved the request, an
authorization code is issued.

If a redirect_uri is specified, Uber's website will redirect the user back to
your application with the authorization code as a GET query string parameter.
You may omit the redirect_uri if you specified it on the Uber website when you
registered your application.

Web application example:

    >>> api = UberAPI(client_id='myclientid',
                      client_secret='myclientsecret',
                      redirect_uri='https://example.com/oauth/callback')
    >>> url = api.get_authorize_url(scopes=['profile', 'history'])

    At this point, you would send the user a 302 redirect or generate a link to
    the URL returned from api.get_authorize_url

    Once the user has completed the OAuth flow, they will be redirected back to
    https://example.com/oauth/callback?code=foobarbaz

    Parse the code from the query string using your web application libraries
    or Python's urlparse.parse_qs method to recover the code, then use it to
    obtain an access token.

    >>> code = 'foobarbaz'  # from HTTP query string
    >>> token = api.get_access_token(code)

    token is now a dict containing access_token, refresh_token, token_type,
    expires_in, and scope keys. You should persist this token information in
    a session store or encrypted cookies. Now you may use these credentials to
    perform subsequent requests to access the user's data.

    >>> products = api.request('GET', '/v1/products',
                               latitude=37.77543,
                               longitude=-122.41890)

    For a complete list of available endpoints and arguments, see
    https://developer.uber.com/v1/endpoints/
'''
import logging
import urlparse
import urllib2
import urllib
import os.path
import httplib
import json
import ssl


class VerifiedHTTPSOpener(urllib2.HTTPSHandler):
    '''
    Verify TLS server certificates against a local root CA bundle

    By default, it uses certificates installed in
    /etc/ssl/certs/ca-certificates.crt which is normally provided by the Debian
    or Ubuntu package named "ca-certificates". On other distributions the root
    CA bundle may be installed in a different location.
    '''
    SSL_CA_CERTS = '/etc/ssl/certs/ca-certificates.crt'

    def https_open(self, req):
        ca_certs = self.SSL_CA_CERTS
        frags = urlparse.urlparse(req.get_full_url())
        ssl.get_server_certificate(
            (frags.hostname, frags.port or 443),
            ca_certs=ca_certs
        )
        return self.do_open(httplib.HTTPSConnection, req)


class UberAPI(object):
    '''
    Client for the Uber API, documented at https://developer.uber.com/
    '''
    OAUTH_BASE = 'https://login.uber.com'
    API_BASE = 'https://api.uber.com'
    USER_AGENT = 'python-uberapi/0.0.1'

    def __init__(self, client_id, client_secret,
                 redirect_uri=None, timeout=5.0, debug=False,
                 ssl_ca_certs='/etc/ssl/certs/ca-certificates.crt'):
        '''
        Create a new Uber API client

        client_id:      Your client_id copied from the Uber website
        client_secret:  Your client_secret copied from the Uber website
        redirect_uri:   Optional OAuth callback URL, must use https and must be
                        registered at https://login.uber.com/applications
        timeout:        Timeout in seconds for all requests to the Uber API.
                        Requests that exceed this timeout will raise an
                        exception.
        debug:          Enables debug level logging
        ssl_ca_certs:   Path to a file containing PEM certificates for
                        trusted root CAs
        '''
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.timeout = timeout
        self.rate_limit_remaining = 0

        self.log = logging.getLogger('uberapi')
        if debug:
            self.log.setLevel(logging.DEBUG)
        else:
            self.log.setLevel(logging.WARNING)

        if ssl_ca_certs is not None:
            if os.path.exists(ssl_ca_certs):
                VerifiedHTTPSOpener.SSL_CA_CERTS = ssl_ca_certs
                self.opener = urllib2.build_opener(VerifiedHTTPSOpener)
            else:
                self.log.warning('ssl_ca_certs "%s" does not exist, server ' +
                                 'certificates will not be verified!',
                                 ssl_ca_certs)
                self.opener = urllib2.build_opener()
        else:
            self.log.warning('No ssl_ca_certs configured, server ' +
                             'certificates will not be verified!')
            self.opener = urllib2.build_opener()

    def get_authorize_url(self, scopes=[], state=None, response_type='code'):
        '''
        Returns a URL to redirect users to to begin the OAuth login flow

        scopes:     List of requested permissions. Available scopes are
                    "profile" and "history"
        state:      Optional nonce value to append to the OAuth callback after
                    successful authentication. This allows you to track a user
                    throughout the full OAuth flow.
        response_type: Type of authorization flow to use. Only "code" is
                       supported at this time and is the default.
        '''
        params = {
            'client_id': self.client_id,
            'response_type': response_type,
            'scopes': ','.join(scopes),
        }

        if state is not None:
            params['state'] = state
        if self.redirect_uri is not None:
            params['redirect_uri'] = self.redirect_uri

        params = urllib.urlencode(params)
        url = '%s?%s' % (self.OAUTH_BASE + '/oauth/authorize', params)
        self.log.debug('Uber API returned authorize url %r', url)
        return url

    def get_access_token(self, code):
        '''
        Exchange the code parameter from an OAuth callback request to your
        redirect_uri for an access token that can be used to perform
        requests on behalf of the authorized user.

        code:       The value of the "code" query string parameter passed
                    by the client to your redirect_uri after successfully
                    authenticating with Uber
        '''
        return self._auth_request('/oauth/token',
                                  client_id=self.client_id,
                                  client_secret=self.client_secret,
                                  grant_type='authorization_code',
                                  code=code)

    def refresh_token(self, refresh_token):
        '''
        Exchange a refresh token received in response to get_access_token
        for a new access token with a later expiration time.

        refresh_token:  The refresh_token value from the get_access_token
                        response.
        '''
        return self._auth_request('/oauth/token',
                                  client_id=self.client_id,
                                  client_secret=self.client_secret,
                                  grant_type='refresh_token',
                                  refresh_token=refresh_token)

    def request(self, method, endpoint, token, **kwargs):
        '''
        Perform a HTTPS request against Uber's API endpoints with an
        authenticated user's access token

        method:     HTTP method (either GET or POST)
        endpoint:   Path to the API endpoint you wish to request
        token:      A valid access_token string
        **kwargs:   Parameters for the given endpoint
        '''
        url = self.API_BASE + endpoint
        params = urllib.urlencode(kwargs)

        if method == 'GET':
            url = '%s?%s' % (url, params)
            req = urllib2.Request(url)
        else:
            req = urllib2.Request(url, data=params)
            req.headers['Content-Type'] = 'application/x-www-form-urlencoded'

        if token is not None:
            req.headers['Authorization'] = 'Bearer %s' % token
        req.headers['User-Agent'] = self.USER_AGENT

        try:
            resp = self.opener.open(req, timeout=self.timeout)
            code = resp.getcode()
            self.log.debug('%i %s %s %s', code, method, url, params)
            self._check_rate_limit(resp)
            return json.load(resp)
        except urllib2.HTTPError as e:
            code = e.code
            msg = e.read()
            self.log.warning('%i %s %s %s', code, method, url, params)
            self.log.warning(msg)
            self._check_rate_limit(e)
            return json.loads(msg)

    def _auth_request(self, endpoint, **kwargs):
        '''
        Perform a HTTPS request against Uber's OAuth endpoints

        You should not need to call this method directly.
        '''
        url = self.OAUTH_BASE + endpoint
        params = kwargs

        if self.redirect_uri is not None:
            params['redirect_uri'] = self.redirect_uri

        params = urllib.urlencode(params)

        req = urllib2.Request(url, data=params)
        req.headers['Content-Type'] = 'application/x-www-form-urlencoded'
        req.headers['User-Agent'] = self.USER_AGENT

        try:
            resp = self.opener.open(req, timeout=self.timeout)
            code = resp.getcode()
            self.log.debug('%i POST %s %s', code, url, params)
            self._check_rate_limit(resp)
            return json.load(resp)
        except urllib2.HTTPError as e:
            code = e.code
            msg = e.read()
            self.log.warning('%i POST %s %s', code, url, params)
            self.log.warning(msg)
            self._check_rate_limit(e)
            return json.loads(msg)

    def _check_rate_limit(self, resp):
        '''
        Write log messages about Uber API rate limit status by parsing
        response headers.
        '''
        remaining = resp.headers.get('X-Rate-Limit-Remaining', None)
        if remaining is None:
            return
        remaining = int(remaining)
        self.rate_limit_remaining = remaining

        self.log.debug('Rate limit remaining: %i', remaining)

        if remaining < 10:
            self.log.warning('Near rate limit, %i requests left', remaining)
        if remaining == 0:
            self.log.error('Rate limit reached')
