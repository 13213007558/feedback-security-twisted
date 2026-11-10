# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Tests for L{twisted.cred}, now with 30% more starch.
"""


import os
import time
from binascii import hexlify, unhexlify

from zope.interface import Interface, implementer

from twisted.cred import checkers, credentials, error, portal
from twisted.internet import defer
from twisted.python import components
from twisted.python.versions import Version
from twisted.trial import unittest

try:
    from crypt import crypt as _crypt  # type: ignore[import-not-found]
except ImportError:
    crypt = None
else:
    crypt = _crypt


# The Twisted version in which UsernameHashedPassword is first deprecated.
_uhpVersion = Version("Twisted", 21, 2, 0)


class ITestable(Interface):
    """
    An interface for a theoretical protocol.
    """

    pass


class TestAvatar:
    """
    A test avatar.
    """

    def __init__(self, name):
        self.name = name
        self.loggedIn = False
        self.loggedOut = False

    def login(self):
        assert not self.loggedIn
        self.loggedIn = True

    def logout(self):
        self.loggedOut = True


@implementer(ITestable)
class Testable(components.Adapter):
    """
    A theoretical protocol for testing.
    """

    pass


components.registerAdapter(Testable, TestAvatar, ITestable)


class IDerivedCredentials(credentials.IUsernamePassword):
    pass


@implementer(IDerivedCredentials, ITestable)
class DerivedCredentials:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def checkPassword(self, password):
        return password == self.password


@implementer(portal.IRealm)
class TestRealm:
    """
    A basic test realm.
    """

    def __init__(self):
        self.avatars = {}

    def requestAvatar(self, avatarId, mind, *interfaces):
        if avatarId in self.avatars:
            avatar = self.avatars[avatarId]
        else:
            avatar = TestAvatar(avatarId)
            self.avatars[avatarId] = avatar
        avatar.login()
        return (interfaces[0], interfaces[0](avatar), avatar.logout)


class CredTests(unittest.TestCase):
    """
    Tests for the meat of L{twisted.cred} -- realms, portals, avatars, and
    checkers.
    """

    def setUp(self):
        self.realm = TestRealm()
        self.portal = portal.Portal(self.realm)
        self.checker = checkers.InMemoryUsernamePasswordDatabaseDontUse()
        self.checker.addUser(b"bob", b"hello")
        self.portal.registerChecker(self.checker)

    def test_listCheckers(self):
        """
        The checkers in a portal can check only certain types of credentials.
        Since this portal has
        L{checkers.InMemoryUsernamePasswordDatabaseDontUse} registered, it
        """
        expected = [credentials.IUsernamePassword, credentials.IUsernameHashedPassword]
        got = self.portal.listCredentialsInterfaces()
        self.assertEqual(sorted(got), sorted(expected))

    def test_basicLogin(self):
        """
        Calling C{login} on a portal with correct credentials and an interface
        that the portal's realm supports works.
        """
        login = self.successResultOf(
            self.portal.login(
                credentials.UsernamePassword(b"bob", b"hello"), self, ITestable
            )
        )
        iface, impl, logout = login

        # whitebox
        self.assertEqual(iface, ITestable)
        self.assertTrue(iface.providedBy(impl), f"{impl} does not implement {iface}")

        # greybox
        self.assertTrue(impl.original.loggedIn)
        self.assertTrue(not impl.original.loggedOut)
        logout()
        self.assertTrue(impl.original.loggedOut)

    def test_derivedInterface(self):
        """
        Logging in with correct derived credentials and an interface
        that the portal's realm supports works.
        """
        login = self.successResultOf(
            self.portal.login(DerivedCredentials(b"bob", b"hello"), self, ITestable)
        )
        iface, impl, logout = login

        # whitebox
        self.assertEqual(iface, ITestable)
        self.assertTrue(iface.providedBy(impl), f"{impl} does not implement {iface}")

        # greybox
        self.assertTrue(impl.original.loggedIn)
        self.assertTrue(not impl.original.loggedOut)
        logout()
        self.assertTrue(impl.original.loggedOut)

    def test_failedLoginPassword(self):
        """
        Calling C{login} with incorrect credentials (in this case a wrong
        password) causes L{error.UnauthorizedLogin} to be raised.
        """
        login = self.failureResultOf(
            self.portal.login(
                credentials.UsernamePassword(b"bob", b"h3llo"), self, ITestable
            )
        )
        self.assertTrue(login)
        self.assertEqual(error.UnauthorizedLogin, login.type)

    def test_failedLoginName(self):
        """
        Calling C{login} with incorrect credentials (in this case no known
        user) causes L{error.UnauthorizedLogin} to be raised.
        """
        login = self.failureResultOf(
            self.portal.login(
                credentials.UsernamePassword(b"jay", b"hello"), self, ITestable
            )
        )
        self.assertTrue(login)
        self.assertEqual(error.UnauthorizedLogin, login.type)


class OnDiskDatabaseTests(unittest.TestCase):
    users = [
        (b"user1", b"pass1"),
        (b"user2", b"pass2"),
        (b"user3", b"pass3"),
    ]

    def setUp(self):
        self.dbfile = self.mktemp()
        with open(self.dbfile, "wb") as f:
            for u, p in self.users:
                f.write(u + b":" + p + b"\n")

    def test_getUserNonexistentDatabase(self):
        """
        A missing db file will cause a permanent rejection of authorization
        attempts.
        """
        self.db = checkers.FilePasswordDB("test_thisbetternoteverexist.db")

        self.assertRaises(error.UnauthorizedLogin, self.db.getUser, "user")

    def testUserLookup(self):
        self.db = checkers.FilePasswordDB(self.dbfile)
        for u, p in self.users:
            self.assertRaises(KeyError, self.db.getUser, u.upper())
            self.assertEqual(self.db.getUser(u), (u, p))

    def testCaseInSensitivity(self):
        self.db = checkers.FilePasswordDB(self.dbfile, caseSensitive=False)
        for u, p in self.users:
            self.assertEqual(self.db.getUser(u.upper()), (u, p))

    def testRequestAvatarId(self):
        self.db = checkers.FilePasswordDB(self.dbfile)
        creds = [credentials.UsernamePassword(u, p) for u, p in self.users]
        d = defer.gatherResults(
            [defer.maybeDeferred(self.db.requestAvatarId, c) for c in creds]
        )
        d.addCallback(self.assertEqual, [u for u, p in self.users])
        return d

    def testRequestAvatarId_hashed(self):
        self.db = checkers.FilePasswordDB(self.dbfile)
        UsernameHashedPassword = self.getDeprecatedModuleAttribute(
            "twisted.cred.credentials", "UsernameHashedPassword", _uhpVersion
        )
        creds = [UsernameHashedPassword(u, p) for u, p in self.users]
        d = defer.gatherResults(
            [defer.maybeDeferred(self.db.requestAvatarId, c) for c in creds]
        )
        d.addCallback(self.assertEqual, [u for u, p in self.users])
        return d


class HashedPasswordOnDiskDatabaseTests(unittest.TestCase):
    users = [
        (b"user1", b"pass1"),
        (b"user2", b"pass2"),
        (b"user3", b"pass3"),
    ]

    def setUp(self):
        dbfile = self.mktemp()
        self.db = checkers.FilePasswordDB(dbfile, hash=self.hash)
        with open(dbfile, "wb") as f:
            for u, p in self.users:
                f.write(u + b":" + self.hash(u, p, u[:2]) + b"\n")

        r = TestRealm()
        self.port = portal.Portal(r)
        self.port.registerChecker(self.db)

    def hash(self, u: bytes, p: bytes, s: bytes) -> bytes:
        hashed_password = crypt(p.decode("ascii"), s.decode("ascii"))  # type: ignore[misc]
        return hashed_password.encode("ascii")  # type: ignore[no-any-return]

    def testGoodCredentials(self):
        goodCreds = [credentials.UsernamePassword(u, p) for u, p in self.users]
        d = defer.gatherResults([self.db.requestAvatarId(c) for c in goodCreds])
        d.addCallback(self.assertEqual, [u for u, p in self.users])
        return d

    def testGoodCredentials_login(self):
        goodCreds = [credentials.UsernamePassword(u, p) for u, p in self.users]
        d = defer.gatherResults(
            [self.port.login(c, None, ITestable) for c in goodCreds]
        )
        d.addCallback(lambda x: [a.original.name for i, a, l in x])
        d.addCallback(self.assertEqual, [u for u, p in self.users])
        return d

    def testBadCredentials(self):
        badCreds = [
            credentials.UsernamePassword(u, b"wrong password") for u, p in self.users
        ]
        d = defer.DeferredList(
            [self.port.login(c, None, ITestable) for c in badCreds], consumeErrors=True
        )
        d.addCallback(self._assertFailures, error.UnauthorizedLogin)
        return d

    def testHashedCredentials(self):
        UsernameHashedPassword = self.getDeprecatedModuleAttribute(
            "twisted.cred.credentials", "UsernameHashedPassword", _uhpVersion
        )
        hashedCreds = [
            UsernameHashedPassword(u, self.hash(None, p, u[:2])) for u, p in self.users
        ]
        d = defer.DeferredList(
            [self.port.login(c, None, ITestable) for c in hashedCreds],
            consumeErrors=True,
        )
        d.addCallback(self._assertFailures, error.UnhandledCredentials)
        return d

    def _assertFailures(self, failures, *expectedFailures):
        for flag, failure in failures:
            self.assertEqual(flag, defer.FAILURE)
            failure.trap(*expectedFailures)
        return None

    if crypt is None:
        skip = "crypt module not available"


class _ControllableHash:
    """
    Stand-in for a slow hash function run by an executor.

    It never performs real hashing or threading: each call records its
    arguments and returns an unfired L{Deferred} which the test resolves by
    hand.  The canceller intentionally does nothing, mirroring work running
    on a thread which cannot be interrupted; cancelling the outer request
    must still fail the login without waiting for that work.
    """

    def __init__(self):
        self.pending = []

    def __call__(self, username, password, storedPassword):
        d = defer.Deferred(canceller=lambda ignored: None)
        self.pending.append((username, password, storedPassword, d))
        return d

    @property
    def deferreds(self):
        return [entry[-1] for entry in self.pending]


class AsyncHashFilePasswordDBTests(unittest.TestCase):
    """
    Tests for L{checkers.FilePasswordDB} when the hash callback returns a
    L{Deferred}, as a slow hash dispatched to an executor would.
    """

    password = b"secret"
    storedHash = b"the-stored-hash"
    wrongHash = b"a-different-hash"

    def setUp(self):
        self.dbfile = self.mktemp()
        with open(self.dbfile, "wb") as f:
            f.write(b"user1:" + self.storedHash + b"\n")
        self.hash = _ControllableHash()
        self.portal = self._makePortal()

    def _makeChecker(self, caseSensitive=True, cache=False):
        return checkers.FilePasswordDB(
            self.dbfile,
            hash=self.hash,
            caseSensitive=caseSensitive,
            cache=cache,
        )

    def _makePortal(self, **kwargs):
        realm = TestRealm()
        port = portal.Portal(realm)
        port.registerChecker(self._makeChecker(**kwargs))
        return port

    def _login(self, username=b"user1", password=None):
        if password is None:
            password = self.password
        return self.portal.login(
            credentials.UsernamePassword(username, password), None, ITestable
        )

    def _avatarName(self, result):
        _iface, impl, _logout = result
        return impl.original.name

    def test_synchronousHashSucceeds(self):
        """
        A hash callback returning a plain value keeps working, so existing
        synchronous callers remain compatible.
        """
        db = checkers.FilePasswordDB(self.dbfile, hash=lambda u, p, s: self.storedHash)
        d = db.requestAvatarId(credentials.UsernamePassword(b"user1", self.password))
        self.assertEqual(self.successResultOf(d), b"user1")

    def test_synchronousHashRaisesFails(self):
        """
        An exception raised synchronously by the hash callback surfaces as a
        failed login rather than being swallowed or treated as a match.
        """

        def brokenHash(username, password, storedPassword):
            raise RuntimeError("hash exploded")

        db = checkers.FilePasswordDB(self.dbfile, hash=brokenHash)
        d = db.requestAvatarId(credentials.UsernamePassword(b"user1", self.password))
        self.assertEqual(
            self.failureResultOf(d, RuntimeError).getErrorMessage(),
            "hash exploded",
        )

    def test_asyncSuccessThroughPortal(self):
        """
        A L{Deferred} returned by the hash callback that resolves to the
        stored hash authenticates the user through L{portal.Portal}.
        """
        d = self._login()
        self.assertNoResult(d)
        self.hash.deferreds[0].callback(self.storedHash)
        self.assertEqual(self._avatarName(self.successResultOf(d)), b"user1")

    def test_asyncWrongPasswordRejected(self):
        """
        An asynchronous hash result that does not equal the stored password
        fails the login with L{error.UnauthorizedLogin}.
        """
        d = self._login(password=b"guessed")
        self.hash.deferreds[0].callback(self.wrongHash)
        self.failureResultOf(d, error.UnauthorizedLogin)

    def test_asyncCallbackFailureRejected(self):
        """
        A failed hash L{Deferred} fails the login with the underlying error
        and never produces an avatar.
        """
        d = self._login()
        self.hash.deferreds[0].errback(RuntimeError("hash exploded"))
        self.assertEqual(
            self.failureResultOf(d, RuntimeError).getErrorMessage(),
            "hash exploded",
        )

    def test_asyncCancelledLoginRejected(self):
        """
        Cancelling the login L{Deferred} fails it with
        L{defer.CancelledError}.  The stand-in executor cannot be
        interrupted, but the cancelled login can never turn into a
        successful authentication.
        """
        d = self._login()
        self.assertNoResult(d)
        d.cancel()
        failure = self.failureResultOf(d, defer.CancelledError)

        # The hash Deferred is already resolved as a cancellation by the
        # time the executor would report back, so there is no pending result
        # left which could grant access.
        self.assertTrue(self.hash.deferreds[0].called)
        self.assertEqual(failure.type, defer.CancelledError)

    def test_lateSuccessCannotOverwriteCancellation(self):
        """
        A later, successful request cannot overwrite the outcome of an
        earlier cancelled one: the cancelled login stays a
        L{defer.CancelledError} failure while the independent request still
        authenticates on its own hash L{Deferred}.
        """
        cancelled = self._login()
        cancelled.cancel()
        cancelledFailure = self.failureResultOf(cancelled, defer.CancelledError)

        # A separately-started request whose hash genuinely matches still
        # authenticates independently, without changing the first result.
        later = self._login()
        self.assertNoResult(later)
        self.hash.deferreds[-1].callback(self.storedHash)
        self.assertEqual(self._avatarName(self.successResultOf(later)), b"user1")
        self.assertEqual(cancelledFailure.type, defer.CancelledError)

    def test_asyncReturnsCanonicalAvatarId(self):
        """
        A case-insensitive database looks up the lowercased username while
        the hash still receives the network-supplied username, and a
        successful asynchronous match returns the canonicalized avatar ID
        read from the file.
        """
        self.portal = self._makePortal(caseSensitive=False)
        d = self._login(username=b"USER1")
        self.assertEqual(self.hash.pending[0][0], b"USER1")
        self.hash.deferreds[0].callback(self.storedHash)
        self.assertEqual(self._avatarName(self.successResultOf(d)), b"user1")

    def test_requestsCompleteInReverseOrder(self):
        """
        Two overlapping logins keep their identities separate when their
        hash L{Deferred}s fire out of order: neither request can resolve to
        the other request's avatar.
        """
        with open(self.dbfile, "wb") as f:
            f.write(b"user1:" + self.storedHash + b"\n")
            f.write(b"user2:" + self.storedHash + b"\n")

        first = self._login(b"user1")
        second = self._login(b"user2")
        self.assertNoResult(first)
        self.assertNoResult(second)

        self.assertEqual(
            [entry[0] for entry in self.hash.pending], [b"user1", b"user2"]
        )

        # The second request's hash completes before the first's.
        self.hash.deferreds[1].callback(self.storedHash)
        self.assertEqual(self._avatarName(self.successResultOf(second)), b"user2")
        self.assertNoResult(first)

        self.hash.deferreds[0].callback(self.storedHash)
        self.assertEqual(self._avatarName(self.successResultOf(first)), b"user1")

    def test_fileChangedWhileHashPending(self):
        """
        A request validates against the credentials read when it started:
        replacing the password file while its hash L{Deferred} is in flight
        neither mixes the two password materials into that request nor
        changes the avatar it resolves to.
        """
        for cache in (False, True):
            with open(self.dbfile, "wb") as f:
                f.write(b"user1:" + self.storedHash + b"\n")
            self.hash = _ControllableHash()
            self.portal = self._makePortal(cache=cache)

            d = self._login()
            self.assertEqual(self.hash.pending[0][2], self.storedHash)

            # Replace the file, giving the user a different hash and forcing
            # a strictly newer mtime so a caching checker must reload it.
            with open(self.dbfile, "wb") as f:
                f.write(b"user1:" + self.wrongHash + b"\n")
            future = time.time() + 10
            os.utime(self.dbfile, (future, future))

            # The in-flight request still compares against the hash it read
            # at the start and succeeds with its original avatar.
            self.hash.deferreds[0].callback(self.storedHash)
            self.assertEqual(self._avatarName(self.successResultOf(d)), b"user1")

            # A fresh request observes the replacement and rejects the old
            # password against the new material.
            newLogin = self._login()
            self.assertEqual(self.hash.pending[-1][2], self.wrongHash)
            self.hash.deferreds[-1].callback(self.storedHash)
            self.failureResultOf(newLogin, error.UnauthorizedLogin)


class CheckersMixin:
    """
    L{unittest.TestCase} mixin for testing that some checkers accept
    and deny specified credentials.

    Subclasses must provide
      - C{getCheckers} which returns a sequence of
        L{checkers.ICredentialChecker}
      - C{getGoodCredentials} which returns a list of 2-tuples of
        credential to check and avaterId to expect.
      - C{getBadCredentials} which returns a list of credentials
        which are expected to be unauthorized.
    """

    @defer.inlineCallbacks
    def test_positive(self):
        """
        The given credentials are accepted by all the checkers, and give
        the expected C{avatarID}s
        """
        for chk in self.getCheckers():
            for cred, avatarId in self.getGoodCredentials():
                r = yield chk.requestAvatarId(cred)
                self.assertEqual(r, avatarId)

    @defer.inlineCallbacks
    def test_negative(self):
        """
        The given credentials are rejected by all the checkers.
        """
        for chk in self.getCheckers():
            for cred in self.getBadCredentials():
                d = chk.requestAvatarId(cred)
                yield self.assertFailure(d, error.UnauthorizedLogin)


class HashlessFilePasswordDBMixin:
    credClass = credentials.UsernamePassword
    diskHash = None

    @staticmethod
    def networkHash(x: bytes) -> bytes:
        return x

    _validCredentials = [
        (b"user1", b"password1"),
        (b"user2", b"password2"),
        (b"user3", b"password3"),
    ]

    def getGoodCredentials(self):
        for u, p in self._validCredentials:
            yield self.credClass(u, self.networkHash(p)), u

    def getBadCredentials(self):
        for u, p in [
            (b"user1", b"password3"),
            (b"user2", b"password1"),
            (b"bloof", b"blarf"),
        ]:
            yield self.credClass(u, self.networkHash(p))

    def getCheckers(self):
        diskHash = self.diskHash or (lambda x: x)
        hashCheck = self.diskHash and (
            lambda username, password, stored: self.diskHash(password)
        )

        for cache in True, False:
            fn = self.mktemp()
            with open(fn, "wb") as fObj:
                for u, p in self._validCredentials:
                    fObj.write(u + b":" + diskHash(p) + b"\n")
            yield checkers.FilePasswordDB(fn, cache=cache, hash=hashCheck)

            fn = self.mktemp()
            with open(fn, "wb") as fObj:
                for u, p in self._validCredentials:
                    fObj.write(diskHash(p) + b" dingle dongle " + u + b"\n")
            yield checkers.FilePasswordDB(fn, b" ", 3, 0, cache=cache, hash=hashCheck)

            fn = self.mktemp()
            with open(fn, "wb") as fObj:
                for u, p in self._validCredentials:
                    fObj.write(
                        b"zip,zap," + u.title() + b",zup," + diskHash(p) + b"\n",
                    )
            yield checkers.FilePasswordDB(
                fn, b",", 2, 4, False, cache=cache, hash=hashCheck
            )


class LocallyHashedFilePasswordDBMixin(HashlessFilePasswordDBMixin):
    @staticmethod
    def diskHash(x):
        return hexlify(x)


class NetworkHashedFilePasswordDBMixin(HashlessFilePasswordDBMixin):
    @staticmethod
    def networkHash(x: bytes) -> bytes:
        return hexlify(x)

    class credClass(credentials.UsernamePassword):
        def checkPassword(self, password):
            return unhexlify(self.password) == password


class HashlessFilePasswordDBCheckerTests(
    HashlessFilePasswordDBMixin, CheckersMixin, unittest.TestCase
):
    pass


class LocallyHashedFilePasswordDBCheckerTests(
    LocallyHashedFilePasswordDBMixin, CheckersMixin, unittest.TestCase
):
    pass


class NetworkHashedFilePasswordDBCheckerTests(
    NetworkHashedFilePasswordDBMixin, CheckersMixin, unittest.TestCase
):
    pass


class UsernameHashedPasswordTests(unittest.TestCase):
    """
    UsernameHashedPassword is a deprecated class that is functionally
    equivalent to UsernamePassword.
    """

    def test_deprecation(self):
        """
        Tests that UsernameHashedPassword is deprecated.
        """
        self.getDeprecatedModuleAttribute(
            "twisted.cred.credentials",
            "UsernameHashedPassword",
            _uhpVersion,
            "Use twisted.cred.credentials.UsernamePassword instead.",
        )
