from .utils import HexToByte

ServerChallenge = HexToByte("01 23 45 67 89 ab cd ef")
ClientChallenge = b'\xaa' * 8
Time = b'\x00' * 8
Workstation = "COMPUTER".encode('utf-16-le')
ServerName = "Server".encode('utf-16-le')
User = "User"
Domain = "Domain"
Password = "Password"
RandomSessionKey = '\55'*16

FAKE_USER = "User"
FAKE_DOMAIN = "Domain"
FAKE_PASSWORD = "Password"

FULL_DOMAIN = '%s\\%s' % (FAKE_DOMAIN, FAKE_USER)

FAKE_URL = u'http://10.0.0.0/nothing'

FAKE_COOKIE_VALUE = "awesome=possum; cool=beans"

CONNECTION_CLOSE = "Close"
CONNECTION_KEEP_ALIVE = "Keep-Alive"

BASIC_AUTH_HEADERS = {
  "server": "Apache-Coyote/1.1",
  "www-authenticate": 'Basic realm="myRealm"',
  "connection": "close",
  "Date": "Tue, 03 Feb 2009 11:47:33 GMT",
  }

INITIAL_REJECTION_HEADERS = {
  "www-authenticate": "NTLM",
  "connection": "close",
  }

INITIAL_REJECTION_BODY = ""

CHALLENGE_RESPONSE_HEADERS = {
  "www-authenticate": "NTLM TlRMTVNTUAACAAAABAAEADgAAAAFgomi3k7KRx+HGYQAAAAAAAAAALQAtAA8AAAABgGwHQAAAA9OAEEAAgAEAE4AQQABABYATgBBAFMAQQBOAEUAWABIAEMAMAA0AAQAHgBuAGEALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQADADYAbgBhAHMAYQBuAGUAeABoAGMAMAA0AC4AbgBhAC4AcQB1AGEAbABjAG8AbQBtAC4AYwBvAG0ABQAiAGMAbwByAHAALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQAHAAgADXHouNLjzAEAAAAA",
  "connection": "close",
  }

CHALLENGE_RESPONSE_HEADERS_WITH_COOKIE = {
  "www-authenticate": "NTLM TlRMTVNTUAACAAAABAAEADgAAAAFgomi3k7KRx+HGYQAAAAAAAAAALQAtAA8AAAABgGwHQAAAA9OAEEAAgAEAE4AQQABABYATgBBAFMAQQBOAEUAWABIAEMAMAA0AAQAHgBuAGEALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQADADYAbgBhAHMAYQBuAGUAeABoAGMAMAA0AC4AbgBhAC4AcQB1AGEAbABjAG8AbQBtAC4AYwBvAG0ABQAiAGMAbwByAHAALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQAHAAgADXHouNLjzAEAAAAA",
  "connection": "close",
  "set-cookie": FAKE_COOKIE_VALUE,
  }

CHALLENGE_RESPONSE_BODY = ""

SUCCESSFUL_CONNECTION_HEADERS = {
  "www-authenticate": "NTLM TlRMTVNTUAACAAAABAAEADgAAAAFgomi3k7KRx+HGYQAAAAAAAAAALQAtAA8AAAABgGwHQAAAA9OAEEAAgAEAE4AQQABABYATgBBAFMAQQBOAEUAWABIAEMAMAA0AAQAHgBuAGEALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQADADYAbgBhAHMAYQBuAGUAeABoAGMAMAA0AC4AbgBhAC4AcQB1AGEAbABjAG8AbQBtAC4AYwBvAG0ABQAiAGMAbwByAHAALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQAHAAgADXHouNLjzAEAAAAA",
  "connection": "close",
  }

SUCCESSFUL_CONNECTION_BODY = "Hello world!"


DUPLICATE_HEADERS = """HTTP/1.1 401 Unauthorized
Server: Apache-Coyote/1.1
WWW-Authenticate: NTLM TlRMTVNTUAACAAAABAAEADgAAAAFgomi3k7KRx+HGYQAAAAAAAAAALQAtAA8AAAABgGwHQAAAA9OAEEAAgAEAE4AQQABABYATgBBAFMAQQBOAEUAWABIAEMAMAA0AAQAHgBuAGEALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQADADYAbgBhAHMAYQBuAGUAeABoAGMAMAA0AC4AbgBhAC4AcQB1AGEAbABjAG8AbQBtAC4AYwBvAG0ABQAiAGMAbwByAHAALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQAHAAgADXHouNLjzAEAAAAA
WWW-Authenticate: Negotiate
Content-Length: 0
Date: Tue, 03 Feb 2009 11:47:33 GMT
Connection: close

"""

AUTH_TOO_SHORT_RESPONSE = """HTTP/1.1 401 Unauthorized
Server: Apache-Coyote/1.1
WWW-Authenticate: NTLM TlRMTVNTUAACAAAAAAAAAAAAAAABAgAAO/AU3OJc3g0=
Content-Length: 0
Date: Tue, 03 Feb 2009 11:47:33 GMT
Connection: close

"""