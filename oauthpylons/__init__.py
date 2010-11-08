# Copyright (c) 2010 Tadas Vilkelisis <vilkeliskis.t@gmail.com>
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from pylons.controllers import WSGIController
from pylons.controllers.util import abort

from oauth2 import (Request as OAuthRequest,
                    Server as OAuthServer,
                    Consumer as OAuthConsumer,
                    Error as OAuthError,
                    SignatureMethod_HMAC_SHA1 as OAuthSignatureMethod_HMAC_SHA1,
                    SignatureMethod_PLAINTEXT as OAuthSignatureMethod_PLAINTEXT
                    )


class InvalidConsumerError(OAuthError):
    pass


class OAuthStoreBase(object):
    """
    Abstract OAuth storage class.
    """
    def lookup_consumer(self, consumer_key):
        """
        This method must perform consumer lookups based on a consumer key
        in your OAuth storage facility. The method must return OAuthConsumer
        instance or its subclass; otherwise raise InvalidConsumerError.
        """
        raise NotImplemented()

    def create_request_token(self, consumer):
        """
        This method must create a new token for the given consumer and
        return an instance of oauth2.Token or its subclass. Additionally you
        might want to store the token so you could retrieve it in later steps.
        """
        raise NotImplemented()



class OAuthPylonsController(WSGIController):
    def __init__(self):
        self.oauth_server = OAuthServer()
        self.oauth_server.add_signature_method(OAuthSignatureMethod_HMAC_SHA1())
        self.oauth_server.add_signature_method(OAuthSignatureMethod_PLAINTEXT())

    def __call__(self, environ, start_response):
        try:
            try:
                #
                # Pylons for whatever reason changes the Authorization http parameter to
                # HTTP_AUTHORIZATION in environ.
                #
                if "HTTP_AUTHORIZATION" in environ:
                    environ['Authorization'] = environ['HTTP_AUTHORIZATION']

                self.oauth_request = OAuthRequest.from_request(http_method = environ['REQUEST_METHOD'],
                        http_url = environ['routes.url'].current(qualified=True) + '?' + environ['QUERY_STRING'],
                        headers = environ,
                        query_string = environ['QUERY_STRING'])
            except:
                pass

            return WSGIController.__call__(self, environ, start_response)
        finally:
            pass
