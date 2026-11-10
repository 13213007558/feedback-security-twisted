# -*- test-case-name: twisted.web.test.test_httpauth -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Implementation of RFC2617: HTTP Digest Authentication

@see: U{http://www.faqs.org/rfcs/rfc2617.html}
"""


import re
from time import time

from zope.interface import implementer

from twisted.cred import credentials, error
from twisted.cred.credentials import (
    IUsernameDigestHash,
    IUsernameHashedPassword,
)
from twisted.internet import defer
from twisted.web.iweb import ICredentialFactory, INonceCountStore

# An RFC 2617 nonce count is exactly eight lower-case hexadecimal digits.
_NONCE_COUNT = re.compile(rb"[0-9a-fA-F]{8}\Z")


@implementer(INonceCountStore)
class NonceCountStore:
    """
    An in-process L{INonceCountStore} implementation.

    For every nonce, and within it every C{(username, cnonce)} pair, the
    highest count committed after a successful authentication is remembered
    together with any counts which are merely reserved while a password
    check is in progress.  Counts reserved by failed password checks are
    rolled back so that error responses never consume a count.

    State is kept in ordinary Python dictionaries: no external database is
    involved.  Entries whose nonces have outlived C{lifetime} are reclaimed
    by L{purge}, which is also run opportunistically from L{reserve}.

    @ivar lifetime: The number of seconds for which the state of a nonce is
        retained.  It should be at least as long as the nonce's own
        lifetime (L{credentials.DigestCredentialFactory.CHALLENGE_LIFETIME_SECS}
        by default).
    @type lifetime: L{float}

    @ivar _clock: A zero-argument callable returning the current time,
        parameterized so the store can be tested deterministically.
    """

    def __init__(
        self,
        lifetime=credentials.DigestCredentialFactory.CHALLENGE_LIFETIME_SECS,
        reactor=None,
    ):
        """
        @param lifetime: See L{lifetime}.
        @type lifetime: L{float}

        @param reactor: A reactor whose C{seconds} method supplies the
            current time.  If L{None}, L{time.time} is used.
        """
        self.lifetime = lifetime
        if reactor is None:
            self._clock = time
        else:
            self._clock = reactor
        # nonce -> (created-at, {pair -> (last-count, set-of-reserved-counts)})
        self._nonces = {}
        self._tokens = {}

    def _getTime(self):
        return self._clock.seconds()

    def reserve(self, nonce, username, cnonce, nonceCount):
        """
        Reserve C{nonceCount} unless it has already been committed or
        reserved, or it is not greater than the last committed count.
        """
        now = self._getTime()
        self.purge(now)

        created, pairs = self._nonces.get(nonce, (now, {}))
        last, reserved = pairs.get((username, cnonce), (0, set()))
        if nonceCount <= last or nonceCount in reserved:
            raise error.LoginFailed(
                "Invalid response, replayed or out-of-order nonce count"
            )
        reserved.add(nonceCount)
        pairs[(username, cnonce)] = (last, reserved)
        self._nonces[nonce] = (created, pairs)

        token = object()
        self._tokens[token] = (nonce, username, cnonce, nonceCount)
        return token

    def commit(self, token):
        """
        Make the reserved count the new last-seen count.
        """
        entry = self._tokens.pop(token, None)
        if entry is None:
            return
        nonce, username, cnonce, nonceCount = entry
        try:
            _created, pairs = self._nonces[nonce]
        except KeyError:
            return
        last, reserved = pairs[(username, cnonce)]
        reserved.discard(nonceCount)
        if nonceCount > last:
            last = nonceCount
        pairs[(username, cnonce)] = (last, reserved)

    def rollback(self, token):
        """
        Release the reservation without advancing the last-seen count.
        """
        entry = self._tokens.pop(token, None)
        if entry is None:
            return
        nonce, username, cnonce, nonceCount = entry
        try:
            _created, pairs = self._nonces[nonce]
        except KeyError:
            return
        last, reserved = pairs[(username, cnonce)]
        reserved.discard(nonceCount)
        pairs[(username, cnonce)] = (last, reserved)

    def purge(self, now=None):
        """
        Reclaim the state of every nonce older than C{lifetime}, including
        any outstanding reservations on it.
        """
        if now is None:
            now = self._getTime()
        expired = [
            nonce
            for nonce, (created, _pairs) in self._nonces.items()
            if now - created > self.lifetime
        ]
        for nonce in expired:
            del self._nonces[nonce]
        if expired:
            self._tokens = {
                token: entry
                for token, entry in self._tokens.items()
                if entry[0] not in expired
            }


@implementer(IUsernameHashedPassword, IUsernameDigestHash)
class _ReplayProtectedDigestedCredentials:
    """
    Wrap L{twisted.cred.credentials.DigestedCredentials} so that a nonce
    count is reserved before the password is checked and only committed once
    the check has succeeded.

    Instances are single use: each C{checkPassword}/C{checkHash} call
    consumes the reservation it makes.
    """

    def __init__(self, credentials, store):
        self._credentials = credentials
        self._store = store
        self.username = credentials.username

    def _run(self, check, secret):
        """
        Reserve the nonce count, run C{check} (which may return a
        L{Deferred}), and commit on success or roll back otherwise.
        """

        def reserved(token):
            def checked(matched):
                if matched:
                    self._store.commit(token)
                else:
                    self._store.rollback(token)
                return matched

            def failed(reason):
                self._store.rollback(token)
                return reason

            d = defer.maybeDeferred(check, secret)
            d.addCallbacks(checked, failed)
            return d

        return defer.maybeDeferred(
            self._store.reserve,
            self._credentials.fields["nonce"],
            self._credentials.username,
            self._credentials.fields["cnonce"],
            int(self._credentials.fields["nc"], 16),
        ).addCallback(reserved)

    def checkPassword(self, password):
        return self._run(self._credentials.checkPassword, password)

    def checkHash(self, digestHash):
        return self._run(self._credentials.checkHash, digestHash)


@implementer(ICredentialFactory)
class DigestCredentialFactory:
    """
    Wrapper for L{digest.DigestCredentialFactory} that implements the
    L{ICredentialFactory} interface.

    @ivar nonceCountStore: An L{INonceCountStore} used to detect replayed
        nonce counts, or L{None} if replay checking is disabled.  An
        application may replace it with any L{INonceCountStore} provider.
    @type nonceCountStore: L{INonceCountStore} provider or L{None}
    """

    scheme = b"digest"

    def __init__(self, algorithm, authenticationRealm, nonceCountStore=None):
        """
        Create the digest credential factory that this object wraps.

        @param nonceCountStore: An L{INonceCountStore} provider enabling
            nonce-count replay protection, or L{None} to keep the historical
            behavior.  Pass a L{NonceCountStore} (or another
            L{INonceCountStore} implementation) to require every response to
            carry a C{qop} of C{'auth'}, a client nonce, and a valid,
            strictly increasing nonce count.  Responses without C{qop} are
            rejected while replay protection is enabled because they cannot
            be distinguished from a replayed request.
        """
        self.digest = credentials.DigestCredentialFactory(
            algorithm, authenticationRealm
        )
        if nonceCountStore is not None and not INonceCountStore.providedBy(
            nonceCountStore
        ):
            raise TypeError(
                "nonceCountStore must provide INonceCountStore or be None"
            )
        self.nonceCountStore = nonceCountStore

    def getChallenge(self, request):
        """
        Generate the challenge for use in the WWW-Authenticate header

        @param request: The L{IRequest} to with access was denied and for the
            response to which this challenge is being generated.

        @return: The L{dict} that can be used to generate a WWW-Authenticate
            header.
        """
        return self.digest.getChallenge(request.getClientAddress().host)

    def decode(self, response, request):
        """
        Create a L{twisted.cred.credentials.DigestedCredentials} object
        from the given response and request.

        When a L{nonceCountStore} is configured, only C{qop=auth} responses
        with a well-formed nonce count and client nonce are accepted, and the
        returned credentials enforce the reserve/commit/rollback protocol of
        the store.  Legacy responses without C{qop}, C{nc}, or C{cnonce} are
        rejected in that mode; without a store the historical behavior is
        preserved and they are accepted.

        @see: L{ICredentialFactory.decode}
        """
        digested = self.digest.decode(
            response, request.method, request.getClientAddress().host
        )
        if self.nonceCountStore is None:
            return digested

        fields = digested.fields
        qop = fields.get("qop")
        cnonce = fields.get("cnonce")
        nonceCount = fields.get("nc")
        if qop != b"auth":
            raise error.LoginFailed(
                "Invalid response, qop must be 'auth' when replay "
                "protection is enabled"
            )
        if not cnonce:
            raise error.LoginFailed(
                "Invalid response, a client nonce is required"
            )
        if not nonceCount or _NONCE_COUNT.fullmatch(nonceCount) is None:
            raise error.LoginFailed(
                "Invalid response, nonce count must be eight hexadecimal "
                "digits"
            )
        return _ReplayProtectedDigestedCredentials(
            digested, self.nonceCountStore
        )
