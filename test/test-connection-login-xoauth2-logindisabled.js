// A server may advertise LOGINDISABLED *and* a usable SASL mechanism at the
// same time -- LOGINDISABLED bans the plaintext LOGIN command only (RFC 3501
// 6.2.3, RFC 2595 5). Exchange Online has been seen doing exactly this. We must
// still authenticate via AUTHENTICATE XOAUTH2 instead of giving up.
//
// See test-connection-login-logindisabled-cleartext.js for the other half of
// this behaviour: over a cleartext link we do NOT send the token.

var assert = require('assert'),
    tls = require('tls'),
    Imap = require('../lib/Connection');

var CRLF = '\r\n';

var XOAUTH2 = 'dXNlcj1mb29AYmFyLmNvbQFhdXRoPUJlYXJlciB0b2tlbgEB';

var RESPONSES = [
  ['* CAPABILITY IMAP4rev1 LOGINDISABLED AUTH=XOAUTH2 SASL-IR NAMESPACE',
   'A0 OK CAPABILITY completed.',
   ''
  ].join(CRLF),
  ['* CAPABILITY IMAP4rev1 NAMESPACE',
   'A1 OK AUTHENTICATE completed.',
   ''
  ].join(CRLF),
  ['* NAMESPACE (("" "/")) NIL NIL',
   'A2 OK NAMESPACE completed.',
   ''
  ].join(CRLF),
  ['* LIST (\\Noselect) "/" "/"',
   'A3 OK LIST completed.',
   ''
  ].join(CRLF)
];
var EXPECTED = [
  'A0 CAPABILITY',
  'A1 AUTHENTICATE XOAUTH2 ' + XOAUTH2,
  'A2 NAMESPACE',
  'A3 LIST "" ""'
];

// Self-signed, valid until 2126 so the test cannot rot.
var KEY = [
'-----BEGIN PRIVATE KEY-----',
'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCVO2E1eFr+Sarf',
'ZxjaWDte2WBrjXgKVvW62sdIkDmbsc34KRjEgYD9bdA0XzQ6RJj1Lt7roS61d1aA',
'40DOTyU9BzA7qSfaGfil9kswOXdO7hpAjAQnr6i9vgjZe44E1bt27TdBZTxr1Ak+',
'ivk/x8kUffCQZYwfZSa3UNZrFyS3x2MRqJ97fN20YomSMGbjzqcJ/48AiXP9Wx6l',
'VX++eqF/nL+zI5cUCrk2kAKQAWtR5itvAA2GSze5PT2/uU80RM5zEceIDJCles6I',
'4HOsiGF7zbsWWaHK6RHoYTSbxB9Lr4Zv/XRrlm1294chgFVt1yNyYYMEXhhaohpg',
'HftowoxxAgMBAAECggEAEYuJTKUtdI1ic7DONxiNxWNi/s4jhXqvGhR//s/nF/8l',
'90XUqcDMkq8rHgct76ZSQexMbPFWuaLR1qYxP7hGKWhLk04aV337cf60nRM6i9r6',
'VumnUOep/AHoTjKEslyTFWLDHvMJMSe9HP9vmcAyS9CZPI7V1DibHk0Yon9Wc61F',
'aojcOshjgJIJ56Hnmer7BafMnA6GwwQcWfMBz4xd0tVBNWDBjj3mDkwxS/RdeuAz',
'vDNXbuyes2oUuuSXsZACh0IVVEajizuHHjSotj9h2MmXWWmY2VlF2hJAzfoj5IH+',
'PFFEsNomuv1s77/goDiSy69eTjS6D/Z3hO5AMmQiCQKBgQDEMzMznBcZpzSfwdNV',
'nqKIjXnuvsK4j+PzU7fwdxZ807fnDobWIitL4YU/XHXLWljJZhd+EFSsdjCzIZzC',
'/QglvjB1t4onAP5tO710MAOqom4VI/JpUHKAtW0A6mXk1tYExv2uyaHmF9EVFb25',
'CJh4OlHwKEdS05OnDm5cRF4puQKBgQDCt21Z+fcKFhLqPGqZRun2Z5is+WvE5Bxb',
'tFBf1h5L/pdzxdNfgEzNDu4HQuPK86E/Yn3yRkV/iWBN5oSe+4eYGymjb3x5wJ/v',
'd0gBMkh7r9+7pHfh5IIMRb48nUPNbuTNlsI2+5irER3vIpIpPFFgvdSKx44X1ucQ',
'MU/lsKF0eQKBgQCRqznurYtxHnWxz2SrAxbFr9TB75v/D8Y82QGOZbyqfT7jLCPs',
'RH5E3nHh8zH6A2A8V7JFhLZ5PV83AFO1acxsyWKNY/IMt24vh9VHuIZgYCy/QWsv',
'yezZptoBfgac+uz3qw6agVXU0gYIU5YDFWCukw5W8nDSDAhqVgqWMqR+8QKBgQCP',
'DuECmEpOWMVw3w6aqqU+agKcI2xwbf//yEy8/L2pq9VuM8wGgGbsyalMIHLoK3Mu',
'9JgAJmztNOtSkKijfb2znVFMSJ61fTaEY6i9aEokxaSlYkLJ7m81wQ/xzMGB75Wf',
'DsKGTvdtx9esWEP2k+BeKVo81DyrezKsjO5cnRciUQKBgG8J2LUYiS2Iu6QTzl3P',
'MzFdqiSmsuekz9ay1TIUg86UCoSi8uhuwLM1b1MH6dtEZIhbXJ5Y3OyRq8LjxlkI',
'm+UOPvQsSY+h0quIDfkJCS5vj3jSiSzq6EokymnS2Sql+zdojc3guNRu2SgH3uyt',
'ufUoOjVQDbgIQtzBfeER95SQ',
'-----END PRIVATE KEY-----'
].join('\n');
var CERT = [
'-----BEGIN CERTIFICATE-----',
'MIIDCzCCAfOgAwIBAgIUHXWdcodg0K5iJzHOew6izzQsFzAwDQYJKoZIhvcNAQEL',
'BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDgxNTAxMjg1OVoYDzIxMjYw',
'NzIyMDEyODU5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB',
'AQUAA4IBDwAwggEKAoIBAQCVO2E1eFr+SarfZxjaWDte2WBrjXgKVvW62sdIkDmb',
'sc34KRjEgYD9bdA0XzQ6RJj1Lt7roS61d1aA40DOTyU9BzA7qSfaGfil9kswOXdO',
'7hpAjAQnr6i9vgjZe44E1bt27TdBZTxr1Ak+ivk/x8kUffCQZYwfZSa3UNZrFyS3',
'x2MRqJ97fN20YomSMGbjzqcJ/48AiXP9Wx6lVX++eqF/nL+zI5cUCrk2kAKQAWtR',
'5itvAA2GSze5PT2/uU80RM5zEceIDJCles6I4HOsiGF7zbsWWaHK6RHoYTSbxB9L',
'r4Zv/XRrlm1294chgFVt1yNyYYMEXhhaohpgHftowoxxAgMBAAGjUzBRMB0GA1Ud',
'DgQWBBQ2MhGq2+5DK8jNw6J1cVlxwZ3RezAfBgNVHSMEGDAWgBQ2MhGq2+5DK8jN',
'w6J1cVlxwZ3RezAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBl',
'k/1GA30QrkhKQnMeb4ZLYxqQ/hvwmy1qLS0zDjoqoQVeZqriswXxT+xRdwo7hIod',
'M7SETb36h0KlI+AcYhrlzQFU3XPx8xa8mOUn5rZxdlMU2B0bmjc01+J3rFnwEh7N',
'CmROL+hEzhJWnZl2rF2JAX1ob8L80atyC0oc6ipiu+SXiVuwjNcJdZjUE4DEAhqL',
'kuiRV1PJcSXWneXpZYvBfDciWGpapa53HPVCjUUkTQkOFokfyluHx2Zvqiz3BN0+',
'eIJ+cK1GvgS7W4U5ONWSpRJCP1qfcEWPtfxaUPrlQnOMv1cH0SvH6WYKY1sr+8Lp',
'cjC6PYkrP+Br4KHeeMKX',
'-----END CERTIFICATE-----'
].join('\n');

var exp = -1,
    res = -1,
    ready = false,
    connErr;

var srv = tls.createServer({ key: KEY, cert: CERT }, function(sock) {
  sock.write('* OK asdf\r\n');
  var buf = '', lines;
  sock.on('error', function() {});
  sock.on('data', function(data) {
    buf += data.toString('utf8');
    if (buf.indexOf(CRLF) > -1) {
      lines = buf.split(CRLF);
      buf = lines.pop();
      lines.forEach(function(l) {
        assert(l === EXPECTED[++exp], 'Unexpected client request: ' + l);
        assert(RESPONSES[++res], 'No response for client request: ' + l);
        sock.write(RESPONSES[res]);
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
    tls: true,
    tlsOptions: { rejectUnauthorized: false, servername: 'localhost' },
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
  assert(connErr === undefined,
         'Expected XOAUTH2 to be attempted despite LOGINDISABLED, got: '
         + (connErr && connErr.message));
  assert(ready, 'Expected the connection to become ready');
  assert.strictEqual(exp, EXPECTED.length - 1,
                     'Client did not send every expected command');
});
