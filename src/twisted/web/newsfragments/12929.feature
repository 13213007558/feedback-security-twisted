twisted.web.guard.DigestCredentialFactory now accepts an optional
``nonceCountStore`` (an ``INonceCountStore`` provider, such as the new
``NonceCountStore``) which enables nonce-count replay protection for
``qop=auth`` digest authentication.  A nonce count is reserved before the
password check and only committed after it succeeds, so failed
authentication never consumes a count and a replayed or out-of-order
``Authorization`` header is rejected.  Legacy responses without ``qop``
are rejected while replay protection is enabled; without a store the
historical behavior is unchanged.
