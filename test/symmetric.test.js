const assert = require('chai').assert;
const chai   = require('chai');

const keys = require('./support/keys');
const bc   = require('../bc');

describe('symmetric keys', function() {

  describe('synchronous', function() {

    describe('direct mode', function() {

      describe('success', function() {

        describe('encryption', function() {

          // express middleware chain for encryption tests
          function encHandler(message) {
            return [
              bc({ symmetric: { key: keys.secretkey } }),
              function(req, res, next) {
                try {
                  var c = req.bc.encrypt(message);
                } catch(ex) {
                  return next(ex);
                }

                req.c = c;

                next();
              },
              function(req, res) {
                res.status(200).json({ ciphertext: req.c });
              }
            ];
          };

          describe('of string input', function() {

            var response;
            var plaintext = 'thisisatestplaintext';

            before(function(done) {
              var handler = encHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return ciphertext and nonce', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.ciphertext);
              assert.ok(/([0-9a-f]+)\*([0-9a-f]{48})/.exec(response.body.ciphertext));

              done();
            });
          });

          describe('of object input', function() {

            var response;
            var plaintext = { thisis: 'atestobject', withinteger: 123, and: { sub: 'objects' } };

            before(function(done) {
              var handler = encHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return ciphertext and nonce', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.ciphertext);
              assert.ok(/([0-9a-f]+)\*([0-9a-f]{48})/.exec(response.body.ciphertext));

              done();
            });
          });
        });

        describe('decryption', function() {

          // express middleware chain for decryption tests
          function decHandler(message, split) {
            return [
              bc({ symmetric: { key: keys.secretkey } }),
              function(req, res, next) {
                try {
                  var c = req.bc.encrypt(message);
                } catch(ex) {
                  return next(ex);
                }

                req.c = c;

                next();
              },
              function(req, res, next) {
                try {
                  if (split) {
                    [req.c, req.n] = req.c.split('*');
                    var m = req.bc.decrypt(req.c,  req.n);
                  } else {
                    var m = req.bc.decrypt(req.c);
                  }
                } catch(ex) {
                  return next(ex);
                }

                req.m = m;

                next();
              },
              function(req, res) {
                res.status(200).json({ plaintext: req.m });
              }
            ];
          };

          describe('of ciphertext constructed with string input', function() {

            var response;
            var plaintext = 'thisisatestplaintext';

            before(function(done) {
              var handler = decHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return plaintext', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.plaintext);
              assert.equal(response.body.plaintext, plaintext);

              done();
            });
          });

          describe('of ciphertext constructed with object input', function() {

            var response;
            var plaintext = { thisis: 'atestobject', withinteger: 123, and: { sub: 'objects' } };

            before(function(done) {
              var handler = decHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return plaintext', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.plaintext);
              assert.equal(response.body.plaintext, JSON.stringify(plaintext)); // TODO: compare objects properly

              done();
            });
          });

          describe('with split ciphertext and nonce', function() {

            var response;
            var plaintext = 'thisisatestplaintext';

            before(function(done) {
              var handler = decHandler(plaintext, true);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return plaintext', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.plaintext);
              assert.equal(response.body.plaintext, plaintext);

              done();
            });
          });
        });
      });

      describe('failure', function() {

        describe('encryption', function() {

          describe('without plaintext', function() {

            before(function (done) {
              var handler = [
                bc({ symmetric: { key: keys.secretkey } }),
                function(req, res, next) {
                  try {
                    var [c, n] = req.bc.encrypt();
                  } catch(ex) {
                    return next(ex);
                  }
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Unable to operate on an empty message.');

              done();
            });
          });
        });

        describe('decryption', function() {

          describe('without ciphertext', function() {

            before(function(done) {
              var handler = [
                bc({ symmetric: { key: keys.secretkey } }),
                function(req, res, next) {
                  try {
                    var m = req.bc.decrypt();
                  } catch(ex) {
                    return next(ex);
                  }
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Unable to operate on an empty message.');

              done();
            });
          });

          describe('without nonce', function() {

            before(function(done) {
              var handler = [
                bc({ symmetric: { key: keys.secretkey } }),
                function(req, res, next) {
                  try {
                    var m = req.bc.decrypt('d9d97c2b267c1be11af605f0682f6e9fbf02d77dd65d4942bdae3053cd4f1eba3c072180');
                  } catch(ex) {
                    return next(ex);
                  }
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Unable to decrypt without nonce.');

              done();
            });
          });
        });
      });
    });

    describe('indirect mode (additional configured cabinets)', function() {

      describe('success', function() {

        describe('encryption', function() {

          // express middleware chain for encryption tests
          function encHandler(message) {
            return [
              bc({ symmetric:  { key: keys.secretkey },
                   asymmetric: { sk:  keys.s_privatekey,
                                 pk:  keys.r_publickey }
                 }),
              function(req, res, next) {
                try {
                  var c = req.bc.encrypt('sym')(message);
                } catch(ex) {
                  return next(ex);
                }

                req.c = c;

                next();
              },
              function(req, res) {
                res.status(200).json({ ciphertext: req.c });
              }
            ];
          };

          describe('of string input', function() {

            var response;
            var plaintext = 'thisisatestplaintext';

            before(function(done) {
              var handler = encHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return ciphertext and nonce', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.ciphertext);
              assert.ok(/([0-9a-f]+)\*([0-9a-f]{48})/.exec(response.body.ciphertext));

              done();
            });
          });

          describe('of object input', function() {

            var response;
            var plaintext = { thisis: 'atestobject', withinteger: 123, and: { sub: 'objects' } };

            before(function(done) {
              var handler = encHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return ciphertext and nonce', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.ciphertext);
              assert.ok(/([0-9a-f]+)\*([0-9a-f]{48})/.exec(response.body.ciphertext));

              done();
            });
          });
        });

        describe('decryption', function() {

          // express middleware chain for decryption tests
          function decHandler(message, split) {
            return [
              bc({ symmetric:  { key: keys.secretkey },
                   asymmetric: { sk:  keys.s_privatekey,
                                 pk:  keys.r_publickey }
                 }),
              function(req, res, next) {
                try {
                  var c = req.bc.encrypt('sym')(message);
                } catch(ex) {
                  return next(ex);
                }

                req.c = c;

                next();
              },
              function(req, res, next) {
                try {
                  if (split) {
                    [req.c, req.n] = req.c.split('*');
                    var m = req.bc.decrypt('sym')(req.c,  req.n);
                  } else {
                    var m = req.bc.decrypt('sym')(req.c);
                  }
                } catch(ex) {
                  return next(ex);
                }

                req.m = m;

                next();
              },
              function(req, res) {
                res.status(200).json({ plaintext: req.m });
              }
            ];
          };

          describe('of ciphertext constructed with string input', function() {

            var response;
            var plaintext = 'thisisatestplaintext';

            before(function(done) {
              var handler = decHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return plaintext', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.plaintext);
              assert.equal(response.body.plaintext, plaintext);

              done();
            });
          });

          describe('of ciphertext constructed with object input', function() {

            var response;
            var plaintext = { thisis: 'atestobject', withinteger: 123, and: { sub: 'objects' } };

            before(function(done) {
              var handler = decHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return plaintext', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.plaintext);
              assert.equal(response.body.plaintext, JSON.stringify(plaintext)); // TODO: compare objects properly

              done();
            });
          });

          describe('with split ciphertext and nonce', function() {

            var response;
            var plaintext = 'thisisatestplaintext';

            before(function(done) {
              var handler = decHandler(plaintext, true);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return plaintext', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.plaintext);
              assert.equal(response.body.plaintext, plaintext);

              done();
            });
          });
        });
      });

      describe('failure', function() {

        describe('encryption', function() {

          describe('attempted direct use', function() {

            before(function (done) {
              var handler = [
                bc({ symmetric:  { key: keys.secretkey },
                     asymmetric: { sk:  keys.s_privatekey,
                                   pk:  keys.r_publickey }
                   }),
                function(req, res, next) {
                  try {
                    var [c, n] = req.bc.encrypt('thisisatestplaintext');
                  } catch(ex) {
                    return next(ex);
                  }
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Please specify \'sym\' (symmetric) or \'asy\' (asymmetric) as the type.');

              done();
            });
          });

          describe('without plaintext', function() {

            before(function (done) {
              var handler = [
                bc({ symmetric:  { key: keys.secretkey },
                     asymmetric: { sk:  keys.s_privatekey,
                                   pk:  keys.r_publickey }
                   }),
                function(req, res, next) {
                  try {
                    var [c, n] = req.bc.encrypt('sym')();
                  } catch(ex) {
                    return next(ex);
                  }
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Unable to operate on an empty message.');

              done();
            });
          });
        });

        describe('decryption', function() {

          describe('attempted direct use', function() {

            before(function(done) {
              var handler = [
                bc({ symmetric:  { key: keys.secretkey },
                     asymmetric: { sk:  keys.s_privatekey,
                                   pk:  keys.r_publickey }
                   }),
                function(req, res, next) {
                  try {
                    var m = req.bc.decrypt('893067c01141b556f4307088b7ced8b7ea7479f1513232ee946da7314ab8c08b6d6a152f*4e1f4e88abf5146e398c319f93e0b49b755dd43c19a0a03c');
                  } catch(ex) {
                    return next(ex);
                  }
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Please specify \'sym\' (symmetric) or \'asy\' (asymmetric) as the type.');

              done();
            });
          });

          describe('without ciphertext', function() {

            before(function(done) {
              var handler = [
                bc({ symmetric:  { key: keys.secretkey },
                     asymmetric: { sk:  keys.s_privatekey,
                                   pk:  keys.r_publickey }
                   }),
                function(req, res, next) {
                  try {
                    var m = req.bc.decrypt('sym')();
                  } catch(ex) {
                    return next(ex);
                  }
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Unable to operate on an empty message.');

              done();
            });
          });

          describe('without nonce', function() {

            before(function(done) {
              var handler = [
                bc({ symmetric:  { key: keys.secretkey },
                     asymmetric: { sk:  keys.s_privatekey,
                                   pk:  keys.r_publickey }
                   }),
                function(req, res, next) {
                  try {
                    var m = req.bc.decrypt('sym')('d9d97c2b267c1be11af605f0682f6e9fbf02d77dd65d4942bdae3053cd4f1eba3c072180');
                  } catch(ex) {
                    return next(ex);
                  }
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Unable to decrypt without nonce.');

              done();
            });
          });
        });
      });
    });
  });

  describe('asynchronous', function() {

    describe('direct mode', function() {

      describe('success', function() {

        describe('encryption', function() {

          // express middleware chain for encryption tests
          function encHandler(message) {
            return [
              bc({ symmetric: { key: keys.secretkey } }),
              function(req, res, next) {
                req.bc.encrypt(message, function(err, c) {
                  if (err) { return next(err); }

                  req.c = c;
                  next();
                });
              },
              function(req, res) {
                res.status(200).json({ ciphertext: req.c });
              }
            ];
          };

          describe('of string input', function() {

            var response;
            var plaintext = 'thisisatestplaintext';

            before(function(done) {
              var handler = encHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return ciphertext and nonce', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.ciphertext);
              assert.ok(/([0-9a-f]+)\*([0-9a-f]{48})/.exec(response.body.ciphertext));

              done();
            });
          });

          describe('of object input', function() {

            var response;
            var plaintext = { thisis: 'atestobject', withinteger: 123, and: { sub: 'objects' } };

            before(function(done) {
              var handler = encHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return ciphertext and nonce', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.ciphertext);
              assert.ok(/([0-9a-f]+)\*([0-9a-f]{48})/.exec(response.body.ciphertext));

              done();
            });
          });
        });

        describe('decryption', function() {

          // express middleware chain for decryption tests
          function decHandler(message, split) {
            return [
              bc({ symmetric: { key: keys.secretkey } }),
              function(req, res, next) {
                req.bc.encrypt(message, function(err, c) {
                  if (err) { return next(err); }

                  req.c = c;
                  next();
                });
              },
              function(req, res, next) {
                if (split) {
                  [req.c, req.n] = req.c.split('*');
                }

                req.bc.decrypt(req.c, req.n, function(err, m) {
                  if (err) { return next(err); }

                  req.m = m;
                  next();
                });
              },
              function(req, res) {
                res.status(200).json({ plaintext: req.m });
              }
            ];
          };

          describe('of ciphertext constructed with string input', function() {

            var response;
            var plaintext = 'thisisatestplaintext';

            before(function(done) {
              var handler = decHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return plaintext', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.plaintext);
              assert.equal(response.body.plaintext, plaintext);

              done();
            });
          });

          describe('of ciphertext constructed with object input', function() {

            var response;
            var plaintext = { thisis: 'atestobject', withinteger: 123, and: { sub: 'objects' } };

            before(function(done) {
              var handler = decHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return plaintext', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.plaintext);
              assert.equal(response.body.plaintext, JSON.stringify(plaintext)); // TODO: compare objects properly

              done();
            });
          });

          describe('with split ciphertext and nonce', function() {

            var response;
            var plaintext = 'thisisatestplaintext';

            before(function(done) {
              var handler = decHandler(plaintext, true);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return plaintext', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.plaintext);
              assert.equal(response.body.plaintext, plaintext);

              done();
            });
          });
        });
      });

      describe('failure', function() {

        describe('encryption', function() {

          describe('without plaintext', function() {

            before(function (done) {
              var handler = [
                bc({ symmetric: { key: keys.secretkey } }),
                function(req, res, next) {
                  req.bc.encrypt(null, function(err, c) {
                    if (err) { return next(err); }
                  });
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Unable to operate on an empty message.');

              done();
            });
          });
        });

        describe('decryption', function() {

          describe('without ciphertext', function() {

            before(function(done) {
              var handler = [
                bc({ symmetric: { key: keys.secretkey } }),
                function(req, res, next) {
                  req.bc.decrypt(null, function(err, m) {
                    if (err) { return next(err); }
                  });
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Unable to operate on an empty message.');

              done();
            });
          });

          describe('without nonce', function() {

            before(function(done) {
              var handler = [
                bc({ symmetric: { key: keys.secretkey } }),
                function(req, res, next) {
                  req.bc.decrypt('d9d97c2b267c1be11af605f0682f6e9fbf02d77dd65d4942bdae3053cd4f1eba3c072180', function(err, m) {
                    if (err) { return next(err); }
                  });
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Unable to decrypt without nonce.');

              done();
            });
          });
        });
      });
    });

    describe('indirect mode (additional configured cabinets)', function() {

      describe('success', function() {

        describe('encryption', function() {

          // express middleware chain for encryption tests
          function encHandler(message) {
            return [
              bc({ symmetric:  { key: keys.secretkey },
                   asymmetric: { sk:  keys.s_privatekey,
                                 pk:  keys.r_publickey }
                 }),
              function(req, res, next) {

                function encrypted(err, c) {
                  if (err) { return next(err); }

                  req.c = c;
                  next();
                }

                return req.bc.encrypt('sym', encrypted)(message);
              },
              function(req, res) {
                res.status(200).json({ ciphertext: req.c });
              }
            ];
          };

          describe('of string input', function() {

            var response;
            var plaintext = 'thisisatestplaintext';

            before(function(done) {
              var handler = encHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return ciphertext and nonce', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.ciphertext);
              assert.ok(/([0-9a-f]+)\*([0-9a-f]{48})/.exec(response.body.ciphertext));

              done();
            });
          });

          describe('of object input', function() {

            var response;
            var plaintext = { thisis: 'atestobject', withinteger: 123, and: { sub: 'objects' } };

            before(function(done) {
              var handler = encHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return ciphertext and nonce', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.ciphertext);
              assert.ok(/([0-9a-f]+)\*([0-9a-f]{48})/.exec(response.body.ciphertext));

              done();
            });
          });
        });

        describe('decryption', function() {

          // express middleware chain for decryption tests
          function decHandler(message, split) {
            return [
              bc({ symmetric:  { key: keys.secretkey },
                   asymmetric: { sk:  keys.s_privatekey,
                                 pk:  keys.r_publickey }
                 }),
              function(req, res, next) {

                function encrypted(err, c) {
                  if (err) { return next(err); }

                  req.c = c;
                  next();
                }

                return req.bc.encrypt('sym', encrypted)(message);
              },
              function(req, res, next) {

                function decrypted(err, m) {
                  if (err) { return next(err); }

                  req.m = m;
                  next();
                }

                if (split) {
                  [req.c, req.n] = req.c.split('*');
                  return req.bc.decrypt('sym', decrypted)(req.c, req.n);
                }

                return req.bc.decrypt('sym', decrypted)(req.c);
              },
              function(req, res) {
                res.status(200).json({ plaintext: req.m });
              }
            ];
          };

          describe('of ciphertext constructed with string input', function() {

            var response;
            var plaintext = 'thisisatestplaintext';

            before(function(done) {
              var handler = decHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return plaintext', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.plaintext);
              assert.equal(response.body.plaintext, plaintext);

              done();
            });
          });

          describe('of ciphertext constructed with object input', function() {

            var response;
            var plaintext = { thisis: 'atestobject', withinteger: 123, and: { sub: 'objects' } };

            before(function(done) {
              var handler = decHandler(plaintext);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return plaintext', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.plaintext);
              assert.equal(response.body.plaintext, JSON.stringify(plaintext)); // TODO: compare objects properly

              done();
            });
          });

          describe('with split ciphertext and nonce', function() {

            var response;
            var plaintext = 'thisisatestplaintext';

            before(function(done) {
              var handler = decHandler(plaintext, true);

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should return plaintext', function(done) {
              assert.ok(response);
              assert.equal(response.statusCode, 200);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.plaintext);
              assert.equal(response.body.plaintext, plaintext);

              done();
            });
          });
        });
      });

      describe('failure', function() {

        describe('encryption', function() {

          describe('attempted direct use', function() {

            before(function (done) {
              var handler = [
                bc({ symmetric:  { key: keys.secretkey },
                     asymmetric: { sk:  keys.s_privatekey,
                                   pk:  keys.r_publickey }
                   }),
                function(req, res, next) {
                  req.bc.encrypt('thisisatestplaintext', function(err, c) {
                    if (err) { return next(err); }
                  });
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Please specify \'sym\' (symmetric) or \'asy\' (asymmetric) as the type.');

              done();
            });
          });

          describe('without plaintext', function() {

            before(function (done) {
              var handler = [
                bc({ symmetric:  { key: keys.secretkey },
                     asymmetric: { sk:  keys.s_privatekey,
                                   pk:  keys.r_publickey }
                   }),
                function(req, res, next) {

                  function encrypted(err, c) {
                    if (err) { return next(err); }
                  }

                  return req.bc.encrypt('sym', encrypted)();
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Unable to operate on an empty message.');

              done();
            });
          });
        });

        describe('decryption', function() {

          describe('attempted direct use', function() {

            before(function(done) {
              var handler = [
                bc({ symmetric:  { key: keys.secretkey },
                     asymmetric: { sk:  keys.s_privatekey,
                                   pk:  keys.r_publickey }
                   }),
                function(req, res, next) {
                  var c = '893067c01141b556f4307088b7ced8b7ea7479f1513232ee946da7314ab8c08b6d6a152f*4e1f4e88abf5146e398c319f93e0b49b755dd43c19a0a03c';

                  req.bc.decrypt(c, function(err, m) {
                    if (err) { return next(err); }
                  });
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Please specify \'sym\' (symmetric) or \'asy\' (asymmetric) as the type.');

              done();
            });
          });

          describe('without ciphertext', function() {

            before(function(done) {
              var handler = [
                bc({ symmetric:  { key: keys.secretkey },
                     asymmetric: { sk:  keys.s_privatekey,
                                   pk:  keys.r_publickey }
                   }),
                function(req, res, next) {

                  function decrypted(err, m) {
                    if (err) { return next(err); }
                  }

                  return req.bc.decrypt('sym', decrypted)();
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Unable to operate on an empty message.');

              done();
            });
          });

          describe('without nonce', function() {

            before(function(done) {
              var handler = [
                bc({ symmetric:  { key: keys.secretkey },
                     asymmetric: { sk:  keys.s_privatekey,
                                   pk:  keys.r_publickey }
                   }),
                function(req, res, next) {

                  function decrypted(err, m) {
                    if (err) { return next(err); }
                  }

                  return req.bc.decrypt('sym', decrypted)('d9d97c2b267c1be11af605f0682f6e9fbf02d77dd65d4942bdae3053cd4f1eba3c072180');
                },
                function(err, req, res, next) {
                  res.status(400).json({ error: err.message });
                }
              ];

              chai.express.handler(handler)
                .end(function(res) {
                  response = res;
                  done();
                })
                .dispatch();
            });

            it('should error', function(done){
              assert.ok(response);
              assert.equal(response.statusCode, 400);
              assert.equal(typeof response, 'object');

              assert.ok(response.body.error);
              assert.equal(response.body.error, 'Unable to decrypt without nonce.');

              done();
            });
          });
        });
      });
    });
  });
});
