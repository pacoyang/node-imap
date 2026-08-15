// SECURITY REGRESSION GUARD -- do not delete alongside the LOGINDISABLED fix.
//
// LOGINDISABLED bans the plaintext LOGIN command only, so over an encrypted
// link we happily fall through to AUTHENTICATE XOAUTH2 (see
// test-connection-login-xoauth2-logindisabled.js). Over a CLEARTEXT link we
// must not: a server that bans plaintext LOGIN is telling us not to put
// credentials on the wire, and an OAuth bearer token is a credential too.
//
// This test fails if someone "simplifies" the fix into an unconditional bypass,
// which would leak the token in the clear.

var assert = require('assert'),
    net = require('net'),
    Imap = require('../lib/Connection');

var CRLF = '\r\n';

var XOAUTH2 = 'dXNlcj1mb29AYmFyLmNvbQFhdXRoPUJlYXJlciB0b2tlbgEB';

var sawAuthenticate = false,
    ready = false,
    connErr;

var srv = net.createServer(function(sock) {
  sock.write('* OK asdf\r\n');
  var buf = '', lines;
  sock.on('error', function() {});
  sock.on('data', function(data) {
    buf += data.toString('utf8');
    if (buf.indexOf(CRLF) > -1) {
      lines = buf.split(CRLF);
      buf = lines.pop();
      lines.forEach(function(l) {
        if (/AUTHENTICATE/i.test(l) || /^\S+ LOGIN /i.test(l))
          sawAuthenticate = true;
        if (l === 'A0 CAPABILITY') {
          sock.write(['* CAPABILITY IMAP4rev1 LOGINDISABLED AUTH=XOAUTH2 '
                        + 'SASL-IR NAMESPACE',
                      'A0 OK CAPABILITY completed.',
                      ''
                     ].join(CRLF));
        }
      });
    }
  });
});
srv.listen(0, '127.0.0.1', function() {
  var port = srv.address().port;
  var imap = new Imap({
    xoauth2: XOAUTH2,
    host: '127.0.0.1',
    port: port,
    authTimeout: 5000
  });
  imap.once('ready', function() {
    ready = true;
    srv.close();
    imap.destroy();
  });
  imap.once('error', function(err) {
    connErr = err;
    srv.close();
  });
  imap.connect();
});

process.once('exit', function() {
  assert(!ready, 'Must not authenticate over cleartext when LOGINDISABLED');
  assert(connErr !== undefined, 'Expected an authentication error');
  assert.strictEqual(connErr.message, 'Logging in is disabled on this server');
  assert.strictEqual(connErr.source, 'authentication');
  assert(!sawAuthenticate,
         'Credentials were sent over a cleartext link that advertised '
         + 'LOGINDISABLED');
});
