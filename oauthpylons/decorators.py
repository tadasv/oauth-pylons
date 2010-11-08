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
#
from oauthpylons import OAuthStoreBase

__all__ = ["oauth_request_token"]


def get_new_kwargs(func, **kwargs):
    #
    # Get the names of arguments of a controller method func.
    # Get rid of the first argument (i.e self, cls...) and construct new kwargs
    # that match arguments of the method.
    #
    varnames = list(func.func_code.co_varnames)
    varnames.pop(0)
    new_kwargs = {}
    for arg in varnames:
        if arg in kwargs['environ']['pylons.routes_dict']:
            new_kwargs[arg] = kwargs['environ']['pylons.routes_dict'][arg]

    return new_kwargs


def oauth_request_token(oauth_store=None,
                        required_params=('oauth_consumer_key',
                                         'oauth_signature_method',
                                         'oauth_signature',
                                         'oauth_timestamp',
                                         'oauth_nonce',
                                         'oauth_callback')
    ):
    if not isinstance(oauth_store, OAuthStoreBase):
        raise TypeError('oauth_store is not an instance of OAuthStoreBase or its subclass.')
    def wrap(f):
        def wrapped_f(self, *args, **kwargs):
            if self.oauth_request == None:
                abort(400, 'Insufficient OAuth arguments.')
            else:
                if not all(k in self.oauth_request for k in required_params):
                    abort(400, 'Insufficient OAuth arguments.')

            try:
                consumer = oauth_store.lookup_consumer(self.oauth_request['oauth_consumer_key'])
                #
                # I catch another exception here because I don't want to reveal the consumer secret passed
                # as the exception message
                #
                try:
                    res = self.oauth_server.verify_request(self.oauth_request, consumer, None)
                except OAuthError:
                    abort(400, 'Invalid OAuth signature')

                #token = oauth_store.create_request_token(consumer)
            except InvalidConsumerError:
                abort(400, 'Invalid OAuth consumer.')
            except OAuthError as e:
                abort(400, str(e))

            result = f(self, *args, get_new_kwargs(f, kwargs))
            return result
        return wrapped_f
    return wrap

