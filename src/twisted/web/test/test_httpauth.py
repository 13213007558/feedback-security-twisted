# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Tests for L{twisted.web._auth}.
"""


import base64

from zope.interface import implementer
from zope.interface.verify import verifyObject

from twisted.cred import error, portal
from twisted.cred._digest import calcHA1, calcHA2, calcResponse
from twisted.cred.checkers import (
    ANONYMOUS,
    AllowAnonymousAccess,
    ICredentialsChecker,
    InMemoryUsernamePasswordDatabaseDontUse,
)
from twisted.cred.credentials import IUsernameHashedPassword, IUsernamePassword
from twisted.internet import defer
from twisted.internet.address import IPv4Address
from twisted.internet.defer import Deferred
from twisted.internet.error import ConnectionDone
from twisted.internet.task import Clock
from twisted.internet.testing import EventLoggingObserver
from twisted.logger import globalLogPublisher
from twisted.python.failure import Failure
from twisted.trial import unittest
from twisted.web._auth import basic, digest
from twisted.web._auth.basic import BasicCredentialFactory
from twisted.web._auth.digest import (
    DigestCredentialFactory,
    NonceCountStore,
)
from twisted.web._auth.wrapper import HTTPAuthSessionWrapper, UnauthorizedResource
from twisted.web.iweb import ICredentialFactory, INonceCountStore
from twisted.web.resource import IResource, Resource, getChildForRequest
from twisted.web.server import NOT_DONE_YET
from twisted.web.static import Data
from twisted.web.test.test_web import DummyRequest


def b64encode(s):
    return base64.b64encode(s).strip()


class BasicAuthTestsMixin:
    """
    L{TestCase} mixin class which defines a number of tests for
    L{basic.BasicCredentialFactory}.  Because this mixin defines C{setUp}, it
    must be inherited before L{TestCase}.
    """

    def setUp(self):
        self.request = self.makeRequest()
        self.realm = b"foo"
        self.username = b"dreid"
        self.password = b"S3CuR1Ty"
        self.credentialFactory = basic.BasicCredentialFactory(self.realm)

    def makeRequest(self, method=b"GET", clientAddress=None):
        """
        Create a request object to be passed to
        L{basic.BasicCredentialFactory.decode} along with a response value.
        Override this in a subclass.
        """
        raise NotImplementedError(f"{self.__class__!r} did not implement makeRequest")

    def test_interface(self):
        """
        L{BasicCredentialFactory} implements L{ICredentialFactory}.
        """
        self.assertTrue(verifyObject(ICredentialFactory, self.credentialFactory))

    def test_usernamePassword(self):
        """
        L{basic.BasicCredentialFactory.decode} turns a base64-encoded response
        into a L{UsernamePassword} object with a password which reflects the
        one which was encoded in the response.
        """
        response = b64encode(b"".join([self.username, b":", self.password]))

        creds = self.credentialFactory.decode(response, self.request)
        self.assertTrue(IUsernamePassword.providedBy(creds))
        self.assertTrue(creds.checkPassword(self.password))
        self.assertFalse(creds.checkPassword(self.password + b"wrong"))

    def test_incorrectPadding(self):
        """
        L{basic.BasicCredentialFactory.decode} decodes a base64-encoded
        response with incorrect padding.
        """
        response = b64encode(b"".join([self.username, b":", self.password]))
        response = response.strip(b"=")

        creds = self.credentialFactory.decode(response, self.request)
        self.assertTrue(verifyObject(IUsernamePassword, creds))
        self.assertTrue(creds.checkPassword(self.password))

    def test_invalidEncoding(self):
        """
        L{basic.BasicCredentialFactory.decode} raises L{LoginFailed} if passed
        a response which is not base64-encoded.
        """
        response = b"x"  # one byte cannot be valid base64 text
        self.assertRaises(
            error.LoginFailed,
            self.credentialFactory.decode,
            response,
            self.makeRequest(),
        )

    def test_invalidCredentials(self):
        """
        L{basic.BasicCredentialFactory.decode} raises L{LoginFailed} when
        passed a response which is not valid base64-encoded text.
        """
        response = b64encode(b"123abc+/")
        self.assertRaises(
            error.LoginFailed,
            self.credentialFactory.decode,
            response,
            self.makeRequest(),
        )


class RequestMixin:
    def makeRequest(self, method=b"GET", clientAddress=None):
        """
        Create a L{DummyRequest} (change me to create a
        L{twisted.web.http.Request} instead).
        """
        if clientAddress is None:
            clientAddress = IPv4Address("TCP", "localhost", 1234)
        request = DummyRequest(b"/")
        request.method = method
        request.client = clientAddress
        return request


class BasicAuthTests(RequestMixin, BasicAuthTestsMixin, unittest.TestCase):
    """
    Basic authentication tests which use L{twisted.web.http.Request}.
    """


class DigestAuthTests(RequestMixin, unittest.TestCase):
    """
    Digest authentication tests which use L{twisted.web.http.Request}.
    """

    def setUp(self):
        """
        Create a DigestCredentialFactory for testing
        """
        self.realm = b"test realm"
        self.algorithm = b"md5"
        self.credentialFactory = digest.DigestCredentialFactory(
            self.algorithm, self.realm
        )
        self.request = self.makeRequest()

    def test_decode(self):
        """
        L{digest.DigestCredentialFactory.decode} calls the C{decode} method on
        L{twisted.cred.digest.DigestCredentialFactory} with the HTTP method and
        host of the request.
        """
        host = b"169.254.0.1"
        method = b"GET"
        done = [False]
        response = object()

        def check(_response, _method, _host):
            self.assertEqual(response, _response)
            self.assertEqual(method, _method)
            self.assertEqual(host, _host)
            done[0] = True

        self.patch(self.credentialFactory.digest, "decode", check)
        req = self.makeRequest(method, IPv4Address("TCP", host, 81))
        self.credentialFactory.decode(response, req)
        self.assertTrue(done[0])

    def test_interface(self):
        """
        L{DigestCredentialFactory} implements L{ICredentialFactory}.
        """
        self.assertTrue(verifyObject(ICredentialFactory, self.credentialFactory))

    def test_getChallenge(self):
        """
        The challenge issued by L{DigestCredentialFactory.getChallenge} must
        include C{'qop'}, C{'realm'}, C{'algorithm'}, C{'nonce'}, and
        C{'opaque'} keys.  The values for the C{'realm'} and C{'algorithm'}
        keys must match the values supplied to the factory's initializer.
        None of the values may have newlines in them.
        """
        challenge = self.credentialFactory.getChallenge(self.request)
        self.assertEqual(challenge["qop"], b"auth")
        self.assertEqual(challenge["realm"], b"test realm")
        self.assertEqual(challenge["algorithm"], b"md5")
        self.assertIn("nonce", challenge)
        self.assertIn("opaque", challenge)
        for v in challenge.values():
            self.assertNotIn(b"\n", v)

    def test_getChallengeWithoutClientIP(self):
        """
        L{DigestCredentialFactory.getChallenge} can issue a challenge even if
        the L{Request} it is passed returns L{None} from C{getClientIP}.
        """
        request = self.makeRequest(b"GET", None)
        challenge = self.credentialFactory.getChallenge(request)
        self.assertEqual(challenge["qop"], b"auth")
        self.assertEqual(challenge["realm"], b"test realm")
        self.assertEqual(challenge["algorithm"], b"md5")
        self.assertIn("nonce", challenge)
        self.assertIn("opaque", challenge)


class DigestReplayMixin:
    """
    Helpers for building digest responses against a factory with a
    controllable clock and a L{NonceCountStore}.
    """

    username = b"foobar"
    password = b"bazquux"
    realmName = b"test realm"
    algorithm = b"md5"
    cnonce = b"29fc54aa1641c6fa0e151419361c8f23"
    uri = b"/write/"
    host = "10.2.3.4"
    method = b"GET"

    def makeFactory(self, lifetime=None):
        clock = Clock()
        store = NonceCountStore(
            lifetime if lifetime is not None else 900, reactor=clock
        )
        factory = DigestCredentialFactory(
            self.algorithm, self.realmName, store
        )
        factory.digest._getTime = clock.seconds
        return factory, store, clock

    def makeRequest(self, method=b"GET"):
        request = DummyRequest([])
        request.method = method
        request.client = IPv4Address("TCP", self.host, 43125)
        return request

    def challenge(self, factory):
        return factory.getChallenge(self.makeRequest())

    def responseHash(self, challenge, nc, cnonce=None, password=None):
        cnonce = self.cnonce if cnonce is None else cnonce
        password = self.password if password is None else password
        ha1 = calcHA1(
            challenge["algorithm"],
            self.username,
            self.realmName,
            password,
            challenge["nonce"],
            cnonce,
        )
        ha2 = calcHA2(
            challenge["algorithm"], self.method, self.uri, b"auth", None
        )
        return calcResponse(
            ha1, ha2, challenge["algorithm"], challenge["nonce"], nc,
            cnonce, b"auth",
        )

    def authorization(self, challenge, nc, cnonce=None, password=None,
                      omit=()):
        """
        Build the value of an I{Authorization} header for the challenge.

        @param password: The password used to calculate the response hash.
            Passing a wrong password yields a header which fails the
            password check but is otherwise well-formed.

        @param omit: Field names to leave out, to exercise the legacy
            no-qop and malformed-count cases.
        """
        cnonce = self.cnonce if cnonce is None else cnonce
        password = self.password if password is None else password
        fields = [
            (b"username", self.username),
            (b"realm", self.realmName),
            (b"algorithm", self.algorithm),
            (b"qop", b"auth"),
            (b"cnonce", cnonce),
            (b"uri", self.uri),
            (b"nc", b"00000001" if nc is None else nc),
            (b"nonce", challenge["nonce"]),
            (b"opaque", challenge["opaque"]),
        ]
        fields.append(
            (b"response", self.responseHash(challenge, nc, cnonce, password))
        )
        return b", ".join(
            b''.join((name, b'="', value, b'"'))
            for name, value in fields
            if name not in omit
        )


class NonceCountStoreTests(DigestReplayMixin, unittest.TestCase):
    """
    Tests for the state machine implemented by L{NonceCountStore}.
    """

    def test_interface(self):
        """
        L{NonceCountStore} implements L{INonceCountStore}.
        """
        _factory, store, _clock = self.makeFactory()
        self.assertTrue(verifyObject(INonceCountStore, store))

    def test_countsMustIncrease(self):
        """
        A count which is not strictly greater than the last committed count
        is refused with L{LoginFailed}.
        """
        _factory, store, _clock = self.makeFactory()
        first = store.reserve(b"nonce", self.username, self.cnonce, 1)
        store.commit(first)
        self.assertRaises(
            error.LoginFailed,
            store.reserve, b"nonce", self.username, self.cnonce, 1,
        )
        self.assertRaises(
            error.LoginFailed,
            store.reserve, b"nonce", self.username, self.cnonce, 0,
        )
        second = store.reserve(b"nonce", self.username, self.cnonce, 2)
        store.commit(second)

    def test_rollbackFreesTheCount(self):
        """
        A rolled-back reservation can be made again, and does not advance
        the last committed count.
        """
        _factory, store, _clock = self.makeFactory()
        token = store.reserve(b"nonce", self.username, self.cnonce, 1)
        store.rollback(token)
        again = store.reserve(b"nonce", self.username, self.cnonce, 1)
        store.commit(again)
        self.assertRaises(
            error.LoginFailed,
            store.reserve, b"nonce", self.username, self.cnonce, 1,
        )

    def test_concurrentReservationsAreSerialized(self):
        """
        Two in-flight reservations for the same count cannot both
        succeed: the second is rejected until the first is rolled back.
        """
        _factory, store, _clock = self.makeFactory()
        first = store.reserve(b"nonce", self.username, self.cnonce, 1)
        self.assertRaises(
            error.LoginFailed,
            store.reserve, b"nonce", self.username, self.cnonce, 1,
        )
        store.rollback(first)
        second = store.reserve(b"nonce", self.username, self.cnonce, 1)
        store.commit(second)

    def test_pairsAreTrackedIndependently(self):
        """
        Different users and client nonces keep independent counters under
        one nonce.
        """
        _factory, store, _clock = self.makeFactory()
        a = store.reserve(b"nonce", self.username, self.cnonce, 1)
        b = store.reserve(b"nonce", b"someone-else", self.cnonce, 1)
        c = store.reserve(b"nonce", self.username, b"other-cnonce", 1)
        store.commit(a)
        store.commit(b)
        store.commit(c)
        self.assertRaises(
            error.LoginFailed,
            store.reserve, b"nonce", self.username, self.cnonce, 1,
        )
        store.reserve(b"nonce", b"someone-else", self.cnonce, 2)

    def test_outOfOrderCommitsKeepTheHighWaterMark(self):
        """
        If a higher count is committed before a lower in-flight count, the
        lower reservation still commits but never lowers the high-water
        mark, so the lower count remains unusable afterwards.
        """
        _factory, store, _clock = self.makeFactory()
        low = store.reserve(b"nonce", self.username, self.cnonce, 1)
        high = store.reserve(b"nonce", self.username, self.cnonce, 2)
        store.commit(high)
        store.commit(low)
        self.assertRaises(
            error.LoginFailed,
            store.reserve, b"nonce", self.username, self.cnonce, 1,
        )
        self.assertRaises(
            error.LoginFailed,
            store.reserve, b"nonce", self.username, self.cnonce, 2,
        )

    def test_purgeReclaimsExpiredNonces(self):
        """
        Once a nonce outlives the store's lifetime, all of its state,
        including outstanding reservations, is reclaimed and its counts
        can start over.  A nonce created afterwards keeps its state.
        """
        _factory, store, clock = self.makeFactory(lifetime=10)
        pending = store.reserve(b"old-nonce", self.username, self.cnonce, 1)
        clock.advance(11)
        store.reserve(b"new-nonce", self.username, self.cnonce, 1)
        store.purge()
        # The dangling reservation token is now unknown and a fresh
        # reservation under the old nonce is accepted again.
        store.rollback(pending)
        store.reserve(b"old-nonce", self.username, self.cnonce, 1)
        # The still-valid nonce keeps its state.
        self.assertRaises(
            error.LoginFailed,
            store.reserve, b"new-nonce", self.username, self.cnonce, 1,
        )

    def test_reservePurgesOpportunistically(self):
        """
        L{NonceCountStore.reserve} reclaims expired nonces on its own, so
        an application never has to call L{purge} explicitly.
        """
        _factory, store, clock = self.makeFactory(lifetime=10)
        store.reserve(b"old-nonce", self.username, self.cnonce, 1)
        clock.advance(11)
        store.reserve(b"old-nonce", self.username, self.cnonce, 1)

    def test_staleTokensAreNoOps(self):
        """
        Committing or rolling back a token which has already been consumed
        or reclaimed does nothing and raises nothing.
        """
        _factory, store, clock = self.makeFactory(lifetime=10)
        token = store.reserve(b"nonce", self.username, self.cnonce, 1)
        store.commit(token)
        store.commit(token)
        store.rollback(token)
        clock.advance(11)
        store.purge()
        store.commit(token)
        store.rollback(token)


class DigestReplayCredentialTests(DigestReplayMixin, unittest.TestCase):
    """
    Tests for L{DigestCredentialFactory} in replay-protected mode at the
    credentials layer.
    """

    def test_disabledByDefault(self):
        """
        Without a store the factory keeps its historical behavior and
        accepts legacy responses without C{qop}, C{nc}, or C{cnonce}.
        """
        factory = DigestCredentialFactory(self.algorithm, self.realmName)
        challenge = factory.getChallenge(self.makeRequest())
        header = self.authorization(challenge, None, omit=(b"qop", b"nc", b"cnonce"))
        creds = factory.decode(header, self.makeRequest())
        self.assertTrue(creds.checkPassword(self.password))

    def test_rejectsStoreWithoutInterface(self):
        """
        Passing something which does not provide L{INonceCountStore} is a
        L{TypeError}.
        """
        self.assertRaises(
            TypeError,
            DigestCredentialFactory, self.algorithm, self.realmName, object(),
        )

    def test_validResponseAuthenticatesAndCommits(self):
        """
        A well-formed response passes and its count is committed so the
        same header can never pass again.
        """
        factory, store, _clock = self.makeFactory()
        challenge = self.challenge(factory)
        header = self.authorization(challenge, b"00000001")
        creds = factory.decode(header, self.makeRequest())
        result = creds.checkPassword(self.password)
        self.assertIsInstance(result, Deferred)
        self.assertEqual(self.successResultOf(result), True)
        replayed = factory.decode(header, self.makeRequest())
        failure = self.failureResultOf(
            replayed.checkPassword(self.password), error.LoginFailed
        )
        self.assertIn("nonce count", str(failure.value))

    def test_replayAfterHigherCount(self):
        """
        Any count at or below the committed high-water mark is rejected.
        """
        factory, store, _clock = self.makeFactory()
        challenge = self.challenge(factory)
        for nc in (b"00000001", b"00000002"):
            creds = factory.decode(
                self.authorization(challenge, nc), self.makeRequest()
            )
            self.assertTrue(
                self.successResultOf(creds.checkPassword(self.password))
            )
        stale = factory.decode(
            self.authorization(challenge, b"00000002"), self.makeRequest()
        )
        self.failureResultOf(stale.checkPassword(self.password), error.LoginFailed)

    def test_wrongPasswordRollsBack(self):
        """
        A response whose password check fails does not consume its count:
        the identical request with the right password succeeds.
        """
        factory, store, _clock = self.makeFactory()
        challenge = self.challenge(factory)
        header = self.authorization(
            challenge, b"00000001", password=self.password + b"wrong"
        )
        bad = factory.decode(header, self.makeRequest())
        self.assertEqual(
            self.successResultOf(bad.checkPassword(self.password)), False
        )
        good = factory.decode(
            self.authorization(challenge, b"00000001"), self.makeRequest()
        )
        self.assertTrue(
            self.successResultOf(good.checkPassword(self.password))
        )

    def test_failedDeferredCheckerRollsBack(self):
        """
        A password check which fails through a L{Deferred} also releases
        the reservation.
        """
        factory, store, _clock = self.makeFactory()
        challenge = self.challenge(factory)

        class FailingCredentials:
            username = b"foobar"

            def checkPassword(self, password):
                return defer.fail(RuntimeError("boom"))

        wrapper = digest._ReplayProtectedDigestedCredentials(
            FailingCredentials(), store
        )
        wrapper._credentials.fields = {
            "nonce": challenge["nonce"],
            "cnonce": self.cnonce,
            "nc": b"00000001",
        }
        self.failureResultOf(
            wrapper.checkPassword(self.password), RuntimeError
        )
        creds = factory.decode(
            self.authorization(challenge, b"00000001"), self.makeRequest()
        )
        self.assertTrue(
            self.successResultOf(creds.checkPassword(self.password))
        )

    def test_deferredCheckerSerializesSameCount(self):
        """
        While a deferred password check holds a reservation, a concurrent
        attempt with the same count fails; only one of the two can ever
        succeed.
        """
        factory, store, _clock = self.makeFactory()
        challenge = self.challenge(factory)

        first = Deferred()

        class SlowCredentials:
            username = b"foobar"

            def checkPassword(self, password):
                return first

        slow = digest._ReplayProtectedDigestedCredentials(SlowCredentials(), store)
        slow._credentials.fields = {
            "nonce": challenge["nonce"],
            "cnonce": self.cnonce,
            "nc": b"00000001",
        }
        pending = slow.checkPassword(self.password)
        self.assertNoResult(pending)

        racing = factory.decode(
            self.authorization(challenge, b"00000001"), self.makeRequest()
        )
        self.failureResultOf(
            racing.checkPassword(self.password), error.LoginFailed
        )

        first.callback(True)
        self.assertEqual(self.successResultOf(pending), True)

    def test_outOfOrderCompletion(self):
        """
        Two deferred checks for increasing counts may finish in reverse
        order without losing either reservation or the high-water mark.
        """
        factory, store, _clock = self.makeFactory()
        challenge = self.challenge(factory)
        lowDeferred = Deferred()
        highDeferred = Deferred()

        class ControlledCredentials:
            username = b"foobar"

            def __init__(self, result):
                self._result = result

            def checkPassword(self, password):
                return self._result

        low = digest._ReplayProtectedDigestedCredentials(
            ControlledCredentials(lowDeferred), store
        )
        low._credentials.fields = {
            "nonce": challenge["nonce"],
            "cnonce": self.cnonce,
            "nc": b"00000001",
        }
        high = digest._ReplayProtectedDigestedCredentials(
            ControlledCredentials(highDeferred), store
        )
        high._credentials.fields = {
            "nonce": challenge["nonce"],
            "cnonce": self.cnonce,
            "nc": b"00000002",
        }
        lowResult = low.checkPassword(self.password)
        highResult = high.checkPassword(self.password)
        highDeferred.callback(True)
        lowDeferred.callback(True)
        self.assertEqual(self.successResultOf(highResult), True)
        self.assertEqual(self.successResultOf(lowResult), True)

        for nc in (b"00000001", b"00000002"):
            replayed = factory.decode(
                self.authorization(challenge, nc), self.makeRequest()
            )
            self.failureResultOf(
                replayed.checkPassword(self.password), error.LoginFailed
            )

    def test_malformedNonceCount(self):
        """
        Nonce counts which are not exactly eight hexadecimal digits are
        rejected at decode time, before any reservation is made.
        """
        factory, store, _clock = self.makeFactory()
        challenge = self.challenge(factory)
        for nc in (b"1", b"0000000G", b"000000001", b""):
            header = self.authorization(challenge, nc)
            self.assertRaises(
                error.LoginFailed, factory.decode, header, self.makeRequest()
            )

    def test_missingClientNonce(self):
        """
        A response without a client nonce is rejected in protected mode.
        """
        factory, store, _clock = self.makeFactory()
        challenge = self.challenge(factory)
        header = self.authorization(
            challenge, b"00000001", omit=(b"cnonce",)
        )
        self.assertRaises(
            error.LoginFailed, factory.decode, header, self.makeRequest()
        )

    def test_legacyNoQopIsRejectedWhenProtected(self):
        """
        The compatibility policy is explicit: with replay protection on,
        legacy responses without C{qop} cannot be replayed safely and are
        rejected rather than accepted.
        """
        factory, store, _clock = self.makeFactory()
        challenge = self.challenge(factory)
        header = self.authorization(
            challenge, None, omit=(b"qop", b"nc", b"cnonce")
        )
        self.assertRaises(
            error.LoginFailed, factory.decode, header, self.makeRequest()
        )

    def test_authIntIsRejected(self):
        """
        Only the advertised C{qop=auth} quality of protection is accepted.
        """
        factory, store, _clock = self.makeFactory()
        challenge = self.challenge(factory)
        header = self.authorization(challenge, b"00000001").replace(
            b'qop="auth"', b'qop="auth-int"'
        )
        self.assertRaises(
            error.LoginFailed, factory.decode, header, self.makeRequest()
        )

    def test_expiredNonceStateIsReusable(self):
        """
        After the store lifetime elapses, the same count under a freshly
        issued nonce is accepted again.
        """
        factory, store, clock = self.makeFactory(lifetime=10)
        firstChallenge = self.challenge(factory)
        creds = factory.decode(
            self.authorization(firstChallenge, b"00000001"),
            self.makeRequest(),
        )
        self.assertTrue(
            self.successResultOf(creds.checkPassword(self.password))
        )
        clock.advance(11)
        secondChallenge = self.challenge(factory)
        creds = factory.decode(
            self.authorization(secondChallenge, b"00000001"),
            self.makeRequest(),
        )
        self.assertTrue(
            self.successResultOf(creds.checkPassword(self.password))
        )

    def test_customStoreIsUsed(self):
        """
        Any L{INonceCountStore} provider can be substituted and receives
        the reservations made by the factory.
        """

        @implementer(INonceCountStore)
        class RecordingStore:
            def __init__(self):
                self.reservations = []
                self.committed = []
                self.rolledBack = []

            def reserve(self, nonce, username, cnonce, nonceCount):
                self.reservations.append((nonce, username, cnonce, nonceCount))
                return ("token", len(self.reservations))

            def commit(self, token):
                self.committed.append(token)

            def rollback(self, token):
                self.rolledBack.append(token)

            def purge(self, now):
                pass

        store = RecordingStore()
        factory = DigestCredentialFactory(
            self.algorithm, self.realmName, store
        )
        challenge = self.challenge(factory)
        creds = factory.decode(
            self.authorization(challenge, b"00000001"), self.makeRequest()
        )
        self.assertTrue(
            self.successResultOf(creds.checkPassword(self.password))
        )
        self.assertEqual(len(store.reservations), 1)
        self.assertEqual(store.reservations[0][1], self.username)
        self.assertEqual(store.reservations[0][2], self.cnonce)
        self.assertEqual(store.reservations[0][3], 1)
        self.assertEqual(len(store.committed), 1)
        self.assertEqual(store.rolledBack, [])


class DigestReplayPortalTests(DigestReplayMixin, unittest.TestCase):
    """
    End-to-end tests driving L{HTTPAuthSessionWrapper} and a L{Portal},
    counting how often the protected resource is actually rendered.
    """

    def setUp(self):
        self.factory, self.store, self.clock = self.makeFactory()
        self.checker = InMemoryUsernamePasswordDatabaseDontUse()
        self.checker.addUser(self.username, self.password)
        self.avatarContent = b"protected write resource"
        self.avatar = Data(self.avatarContent, "text/plain")
        self.realm = Realm({self.username: self.avatar}.get)
        self.portal = portal.Portal(self.realm, [self.checker])
        self.wrapper = HTTPAuthSessionWrapper(
            self.portal, [self.factory]
        )

    def dispatch(self, header):
        request = self.makeRequest()
        request.requestHeaders.addRawHeader(
            b"authorization", b"Digest " + header
        )
        child = getChildForRequest(self.wrapper, request)
        request.render(child)
        return request

    def test_challengeThenLegitimateRequest(self):
        """
        A request without credentials gets a 401 challenge; a correct
        response to it reaches the protected resource exactly once.
        """
        challenged = self.makeRequest()
        child = getChildForRequest(self.wrapper, challenged)
        challenged.render(child)
        self.assertEqual(challenged.responseCode, 401)
        self.assertEqual(
            challenged.responseHeaders.getRawHeaders(b"www-authenticate")[0][:6],
            b"digest",
        )

        challenge = self.factory.getChallenge(self.makeRequest())
        request = self.dispatch(
            self.authorization(challenge, b"00000001")
        )
        self.assertEqual(request.written, [self.avatarContent])
        self.assertEqual(self.realm.loggedIn, 1)

    def test_replayNeverReachesResource(self):
        """
        Replaying an accepted Authorization header yields a 401 and does
        not render the protected resource a second time.
        """
        challenge = self.factory.getChallenge(self.makeRequest())
        header = self.authorization(challenge, b"00000001")
        first = self.dispatch(header)
        self.assertEqual(first.written, [self.avatarContent])

        replayed = self.dispatch(header)
        self.assertEqual(replayed.responseCode, 401)
        self.assertEqual(replayed.written, [b"Unauthorized"])
        self.assertEqual(self.realm.loggedIn, 1)

    def test_wrongPasswordDoesNotConsumeCount(self):
        """
        A wrong-password 401 leaves the count free for a later correct
        request, which reaches the resource.
        """
        challenge = self.factory.getChallenge(self.makeRequest())
        bad = self.dispatch(
            self.authorization(
                challenge, b"00000001", password=self.password + b"no"
            )
        )
        self.assertEqual(bad.responseCode, 401)
        self.assertEqual(self.realm.loggedIn, 0)

        good = self.dispatch(
            self.authorization(challenge, b"00000001")
        )
        self.assertEqual(good.written, [self.avatarContent])
        self.assertEqual(self.realm.loggedIn, 1)

    def test_concurrentSameCountOnlyOneSucceeds(self):
        """
        Two requests presenting the same nonce count, checked
        concurrently through deferred checkers, cannot both reach the
        resource: while the first password check is still in flight, the
        second request is rejected at reservation time.
        """
        challenge = self.factory.getChallenge(self.makeRequest())
        inFlight = Deferred()
        password = self.password

        @implementer(ICredentialsChecker)
        class DeferredChecker:
            credentialInterfaces = (IUsernameHashedPassword,)

            def requestAvatarId(self, credentials):
                # Replace the synchronous hash check with one which stays
                # pending, so the first request holds its reservation while
                # a second request arrives.
                def deferredCheck(_secret):
                    return inFlight

                credentials._credentials.checkPassword = deferredCheck
                checked = credentials.checkPassword(password)

                def matched(ok):
                    if not ok:
                        raise error.UnauthorizedLogin()
                    return credentials.username

                return checked.addCallback(matched)

        self.portal.registerChecker(DeferredChecker())

        def begin(header):
            request = self.makeRequest()
            request.requestHeaders.addRawHeader(
                b"authorization", b"Digest " + header
            )
            child = getChildForRequest(self.wrapper, request)
            request.render(child)
            return request

        header = self.authorization(challenge, b"00000001")
        first = begin(header)
        self.assertEqual(first.written, [])
        second = begin(header)
        # The racing request cannot reserve the count and is rejected
        # before its password check runs.
        self.assertEqual(second.responseCode, 401)
        self.assertEqual(second.written, [b"Unauthorized"])
        self.assertEqual(self.realm.loggedIn, 0)

        inFlight.callback(True)
        self.assertEqual(first.written, [self.avatarContent])
        self.assertEqual(self.realm.loggedIn, 1)

    def test_legacyNoQopRequestRejected(self):
        """
        A legacy client which omits C{qop} is challenged again and never
        reaches the resource while replay protection is enabled.
        """
        challenge = self.factory.getChallenge(self.makeRequest())
        request = self.dispatch(
            self.authorization(
                challenge, None, omit=(b"qop", b"nc", b"cnonce")
            )
        )
        self.assertEqual(request.responseCode, 401)
        self.assertEqual(self.realm.loggedIn, 0)

    def test_expiredNonceAllowsFreshSequence(self):
        """
        Once the clock passes the store lifetime, a new challenge starts a
        fresh count sequence which reaches the resource.
        """
        challenge = self.factory.getChallenge(self.makeRequest())
        self.dispatch(self.authorization(challenge, b"00000001"))
        self.clock.advance(self.store.lifetime + 1)
        fresh = self.factory.getChallenge(self.makeRequest())
        request = self.dispatch(
            self.authorization(fresh, b"00000001")
        )
        self.assertEqual(request.written, [self.avatarContent])
        self.assertEqual(self.realm.loggedIn, 2)


class UnauthorizedResourceTests(RequestMixin, unittest.TestCase):
    """
    Tests for L{UnauthorizedResource}.
    """

    def test_getChildWithDefault(self):
        """
        An L{UnauthorizedResource} is every child of itself.
        """
        resource = UnauthorizedResource([])
        self.assertIdentical(resource.getChildWithDefault("foo", None), resource)
        self.assertIdentical(resource.getChildWithDefault("bar", None), resource)

    def _unauthorizedRenderTest(self, request):
        """
        Render L{UnauthorizedResource} for the given request object and verify
        that the response code is I{Unauthorized} and that a I{WWW-Authenticate}
        header is set in the response containing a challenge.
        """
        resource = UnauthorizedResource([BasicCredentialFactory("example.com")])
        request.render(resource)
        self.assertEqual(request.responseCode, 401)
        self.assertEqual(
            request.responseHeaders.getRawHeaders(b"www-authenticate"),
            [b'basic realm="example.com"'],
        )

    def test_render(self):
        """
        L{UnauthorizedResource} renders with a 401 response code and a
        I{WWW-Authenticate} header and puts a simple unauthorized message
        into the response body.
        """
        request = self.makeRequest()
        self._unauthorizedRenderTest(request)
        self.assertEqual(b"Unauthorized", b"".join(request.written))

    def test_renderHEAD(self):
        """
        The rendering behavior of L{UnauthorizedResource} for a I{HEAD} request
        is like its handling of a I{GET} request, but no response body is
        written.
        """
        request = self.makeRequest(method=b"HEAD")
        self._unauthorizedRenderTest(request)
        self.assertEqual(b"", b"".join(request.written))

    def test_renderQuotesRealm(self):
        """
        The realm value included in the I{WWW-Authenticate} header set in
        the response when L{UnauthorizedResounrce} is rendered has quotes
        and backslashes escaped.
        """
        resource = UnauthorizedResource([BasicCredentialFactory('example\\"foo')])
        request = self.makeRequest()
        request.render(resource)
        self.assertEqual(
            request.responseHeaders.getRawHeaders(b"www-authenticate"),
            [b'basic realm="example\\\\\\"foo"'],
        )

    def test_renderQuotesDigest(self):
        """
        The digest value included in the I{WWW-Authenticate} header
        set in the response when L{UnauthorizedResource} is rendered
        has quotes and backslashes escaped.
        """
        resource = UnauthorizedResource(
            [digest.DigestCredentialFactory(b"md5", b'example\\"foo')]
        )
        request = self.makeRequest()
        request.render(resource)
        authHeader = request.responseHeaders.getRawHeaders(b"www-authenticate")[0]
        self.assertIn(b'realm="example\\\\\\"foo"', authHeader)
        self.assertIn(b'hm="md5', authHeader)


implementer(portal.IRealm)


class Realm:
    """
    A simple L{IRealm} implementation which gives out L{WebAvatar} for any
    avatarId.

    @type loggedIn: C{int}
    @ivar loggedIn: The number of times C{requestAvatar} has been invoked for
        L{IResource}.

    @type loggedOut: C{int}
    @ivar loggedOut: The number of times the logout callback has been invoked.
    """

    def __init__(self, avatarFactory):
        self.loggedOut = 0
        self.loggedIn = 0
        self.avatarFactory = avatarFactory

    def requestAvatar(self, avatarId, mind, *interfaces):
        if IResource in interfaces:
            self.loggedIn += 1
            return IResource, self.avatarFactory(avatarId), self.logout
        raise NotImplementedError()

    def logout(self):
        self.loggedOut += 1


class HTTPAuthHeaderTests(unittest.TestCase):
    """
    Tests for L{HTTPAuthSessionWrapper}.
    """

    makeRequest = DummyRequest

    def setUp(self):
        """
        Create a realm, portal, and L{HTTPAuthSessionWrapper} to use in the tests.
        """
        self.username = b"foo bar"
        self.password = b"bar baz"
        self.avatarContent = b"contents of the avatar resource itself"
        self.childName = b"foo-child"
        self.childContent = b"contents of the foo child of the avatar"
        self.checker = InMemoryUsernamePasswordDatabaseDontUse()
        self.checker.addUser(self.username, self.password)
        self.avatar = Data(self.avatarContent, "text/plain")
        self.avatar.putChild(self.childName, Data(self.childContent, "text/plain"))
        self.avatars = {self.username: self.avatar}
        self.realm = Realm(self.avatars.get)
        self.portal = portal.Portal(self.realm, [self.checker])
        self.credentialFactories = []
        self.wrapper = HTTPAuthSessionWrapper(self.portal, self.credentialFactories)

    def _authorizedBasicLogin(self, request):
        """
        Add an I{basic authorization} header to the given request and then
        dispatch it, starting from C{self.wrapper} and returning the resulting
        L{IResource}.
        """
        authorization = b64encode(self.username + b":" + self.password)
        request.requestHeaders.addRawHeader(b"authorization", b"Basic " + authorization)
        return getChildForRequest(self.wrapper, request)

    def test_getChildWithDefault(self):
        """
        Resource traversal which encounters an L{HTTPAuthSessionWrapper}
        results in an L{UnauthorizedResource} instance when the request does
        not have the required I{Authorization} headers.
        """
        request = self.makeRequest([self.childName])
        child = getChildForRequest(self.wrapper, request)
        d = request.notifyFinish()

        def cbFinished(result):
            self.assertEqual(request.responseCode, 401)

        d.addCallback(cbFinished)
        request.render(child)
        return d

    def _invalidAuthorizationTest(self, response):
        """
        Create a request with the given value as the value of an
        I{Authorization} header and perform resource traversal with it,
        starting at C{self.wrapper}.  Assert that the result is a 401 response
        code.  Return a L{Deferred} which fires when this is all done.
        """
        self.credentialFactories.append(BasicCredentialFactory("example.com"))
        request = self.makeRequest([self.childName])
        request.requestHeaders.addRawHeader(b"authorization", response)
        child = getChildForRequest(self.wrapper, request)
        d = request.notifyFinish()

        def cbFinished(result):
            self.assertEqual(request.responseCode, 401)

        d.addCallback(cbFinished)
        request.render(child)
        return d

    def test_getChildWithDefaultUnauthorizedUser(self):
        """
        Resource traversal which enouncters an L{HTTPAuthSessionWrapper}
        results in an L{UnauthorizedResource} when the request has an
        I{Authorization} header with a user which does not exist.
        """
        return self._invalidAuthorizationTest(b"Basic " + b64encode(b"foo:bar"))

    def test_getChildWithDefaultUnauthorizedPassword(self):
        """
        Resource traversal which enouncters an L{HTTPAuthSessionWrapper}
        results in an L{UnauthorizedResource} when the request has an
        I{Authorization} header with a user which exists and the wrong
        password.
        """
        return self._invalidAuthorizationTest(
            b"Basic " + b64encode(self.username + b":bar")
        )

    def test_getChildWithDefaultUnrecognizedScheme(self):
        """
        Resource traversal which enouncters an L{HTTPAuthSessionWrapper}
        results in an L{UnauthorizedResource} when the request has an
        I{Authorization} header with an unrecognized scheme.
        """
        return self._invalidAuthorizationTest(b"Quux foo bar baz")

    def test_getChildWithDefaultAuthorized(self):
        """
        Resource traversal which encounters an L{HTTPAuthSessionWrapper}
        results in an L{IResource} which renders the L{IResource} avatar
        retrieved from the portal when the request has a valid I{Authorization}
        header.
        """
        self.credentialFactories.append(BasicCredentialFactory("example.com"))
        request = self.makeRequest([self.childName])
        child = self._authorizedBasicLogin(request)
        d = request.notifyFinish()

        def cbFinished(ignored):
            self.assertEqual(request.written, [self.childContent])

        d.addCallback(cbFinished)
        request.render(child)
        return d

    def test_renderAuthorized(self):
        """
        Resource traversal which terminates at an L{HTTPAuthSessionWrapper}
        and includes correct authentication headers results in the
        L{IResource} avatar (not one of its children) retrieved from the
        portal being rendered.
        """
        self.credentialFactories.append(BasicCredentialFactory("example.com"))
        # Request it exactly, not any of its children.
        request = self.makeRequest([])
        child = self._authorizedBasicLogin(request)
        d = request.notifyFinish()

        def cbFinished(ignored):
            self.assertEqual(request.written, [self.avatarContent])

        d.addCallback(cbFinished)
        request.render(child)
        return d

    def test_getChallengeCalledWithRequest(self):
        """
        When L{HTTPAuthSessionWrapper} finds an L{ICredentialFactory} to issue
        a challenge, it calls the C{getChallenge} method with the request as an
        argument.
        """

        @implementer(ICredentialFactory)
        class DumbCredentialFactory:
            scheme = b"dumb"

            def __init__(self):
                self.requests = []

            def getChallenge(self, request):
                self.requests.append(request)
                return {}

        factory = DumbCredentialFactory()
        self.credentialFactories.append(factory)
        request = self.makeRequest([self.childName])
        child = getChildForRequest(self.wrapper, request)
        d = request.notifyFinish()

        def cbFinished(ignored):
            self.assertEqual(factory.requests, [request])

        d.addCallback(cbFinished)
        request.render(child)
        return d

    def _logoutTest(self):
        """
        Issue a request for an authentication-protected resource using valid
        credentials and then return the C{DummyRequest} instance which was
        used.

        This is a helper for tests about the behavior of the logout
        callback.
        """
        self.credentialFactories.append(BasicCredentialFactory("example.com"))

        class SlowerResource(Resource):
            def render(self, request):
                return NOT_DONE_YET

        self.avatar.putChild(self.childName, SlowerResource())
        request = self.makeRequest([self.childName])
        child = self._authorizedBasicLogin(request)
        request.render(child)
        self.assertEqual(self.realm.loggedOut, 0)
        return request

    def test_logout(self):
        """
        The realm's logout callback is invoked after the resource is rendered.
        """
        request = self._logoutTest()
        request.finish()
        self.assertEqual(self.realm.loggedOut, 1)

    def test_logoutOnError(self):
        """
        The realm's logout callback is also invoked if there is an error
        generating the response (for example, if the client disconnects
        early).
        """
        request = self._logoutTest()
        request.processingFailed(Failure(ConnectionDone("Simulated disconnect")))
        self.assertEqual(self.realm.loggedOut, 1)

    def test_decodeRaises(self):
        """
        Resource traversal which enouncters an L{HTTPAuthSessionWrapper}
        results in an L{UnauthorizedResource} when the request has a I{Basic
        Authorization} header which cannot be decoded using base64.
        """
        self.credentialFactories.append(BasicCredentialFactory("example.com"))
        request = self.makeRequest([self.childName])
        request.requestHeaders.addRawHeader(
            b"authorization", b"Basic decode should fail"
        )
        child = getChildForRequest(self.wrapper, request)
        self.assertIsInstance(child, UnauthorizedResource)

    def test_selectParseResponse(self):
        """
        L{HTTPAuthSessionWrapper._selectParseHeader} returns a two-tuple giving
        the L{ICredentialFactory} to use to parse the header and a string
        containing the portion of the header which remains to be parsed.
        """
        basicAuthorization = b"Basic abcdef123456"
        self.assertEqual(
            self.wrapper._selectParseHeader(basicAuthorization), (None, None)
        )
        factory = BasicCredentialFactory("example.com")
        self.credentialFactories.append(factory)
        self.assertEqual(
            self.wrapper._selectParseHeader(basicAuthorization),
            (factory, b"abcdef123456"),
        )

    def test_unexpectedDecodeError(self):
        """
        Any unexpected exception raised by the credential factory's C{decode}
        method results in a 500 response code and causes the exception to be
        logged.
        """
        logObserver = EventLoggingObserver.createWithCleanup(self, globalLogPublisher)

        class UnexpectedException(Exception):
            pass

        class BadFactory:
            scheme = b"bad"

            def getChallenge(self, client):
                return {}

            def decode(self, response, request):
                raise UnexpectedException()

        self.credentialFactories.append(BadFactory())
        request = self.makeRequest([self.childName])
        request.requestHeaders.addRawHeader(b"authorization", b"Bad abc")
        child = getChildForRequest(self.wrapper, request)
        request.render(child)
        self.assertEqual(request.responseCode, 500)
        self.assertEqual(1, len(logObserver))
        self.assertIsInstance(logObserver[0]["log_failure"].value, UnexpectedException)
        self.assertEqual(len(self.flushLoggedErrors(UnexpectedException)), 1)

    def test_unexpectedLoginError(self):
        """
        Any unexpected failure from L{Portal.login} results in a 500 response
        code and causes the failure to be logged.
        """
        logObserver = EventLoggingObserver.createWithCleanup(self, globalLogPublisher)

        class UnexpectedException(Exception):
            pass

        class BrokenChecker:
            credentialInterfaces = (IUsernamePassword,)

            def requestAvatarId(self, credentials):
                raise UnexpectedException()

        self.portal.registerChecker(BrokenChecker())
        self.credentialFactories.append(BasicCredentialFactory("example.com"))
        request = self.makeRequest([self.childName])
        child = self._authorizedBasicLogin(request)
        request.render(child)
        self.assertEqual(request.responseCode, 500)
        self.assertEqual(1, len(logObserver))
        self.assertIsInstance(logObserver[0]["log_failure"].value, UnexpectedException)
        self.assertEqual(len(self.flushLoggedErrors(UnexpectedException)), 1)

    def test_anonymousAccess(self):
        """
        Anonymous requests are allowed if a L{Portal} has an anonymous checker
        registered.
        """
        unprotectedContents = b"contents of the unprotected child resource"

        self.avatars[ANONYMOUS] = Resource()
        self.avatars[ANONYMOUS].putChild(
            self.childName, Data(unprotectedContents, "text/plain")
        )
        self.portal.registerChecker(AllowAnonymousAccess())

        self.credentialFactories.append(BasicCredentialFactory("example.com"))
        request = self.makeRequest([self.childName])
        child = getChildForRequest(self.wrapper, request)
        d = request.notifyFinish()

        def cbFinished(ignored):
            self.assertEqual(request.written, [unprotectedContents])

        d.addCallback(cbFinished)
        request.render(child)
        return d
