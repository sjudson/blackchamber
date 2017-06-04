const assert = require('chai').assert;
const chai   = require('chai');

const keys = require('./support/keys');
const bc   = require('../bc');

describe('asymmetric keys (direct mode)', function() {

  describe('success', function() {

    describe('encryption', function() {

      // express middleware chain for encryption tests
      function encHandler(message) {
	return [
	  bc({ asymmetric: { sk: keys.s_privatekey, pk: keys.r_publickey } }),
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
	  var handler = encHandler(plaintext, 'asy');

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
	  var handler = encHandler(plaintext, 'asy');

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
	  bc({ asymmetric: { sk: keys.s_privatekey, pk: keys.r_publickey } }),
	  bc('un', { asymmetric: { sk: keys.r_privatekey, pk: keys.s_publickey } }),
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
		var m = req.un.decrypt(req.c,  req.n);
	      } else {
		var m = req.un.decrypt(req.c);
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
	    bc({ asymmetric: { sk: keys.s_privatekey, pk: keys.r_publickey } }),
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
	    bc({ asymmetric: { sk: keys.s_privatekey, pk: keys.r_publickey } }),
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
	    bc({ asymmetric: { sk: keys.s_privatekey, pk: keys.r_publickey } }),
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
