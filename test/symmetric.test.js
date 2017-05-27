const assert = require('chai').assert;
const chai   = require('chai');

const keys = require('./support/keys');
const bc   = require('../bc');

describe('symmetric keys', function() {

  describe('success', function() {

    describe('encryption', function() {

      // express middleware chain for encryption tests
      function encHandler(message, type) {
	return [
	  bc({ symmetric: { key: keys.secretkey } }),
	  function(req, res, next) {
	    try {
	      var [c, n] = req.bc(message, type);
	    } catch(ex) {
	      return next(ex);
	    }

	    req.c = c;
	    req.n = n;

	    next();
	  },
	  function(req, res) {
	    res.status(200).json({ ciphertext: req.c, nonce: req.n });
	  },
	  function(err, req, res, next) {
	    res.status(400).json({ error: err.message });
	  }
	];
      };

      describe('of string input', function() {

	var response;
	var plaintext = 'thisisatestplaintext';

	before(function(done) {
	  var handler = encHandler(plaintext, 'sym');

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
	  assert.ok(/[0-9a-f]{64}/.exec(response.body.ciphertext));

	  assert.ok(response.body.nonce);
	  assert.ok(/[0-9a-f]{48}/.exec(response.body.nonce));

	  done();
	});
      });

      describe('of object input', function() {

	var response;
	var plaintext = { thisis: 'atestobject', withinteger: 123, and: { sub: 'objects' } };

	before(function(done) {
	  var handler = encHandler(plaintext, 'sym');

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
	  assert.ok(/[0-9a-f]{64}/.exec(response.body.ciphertext));

	  assert.ok(response.body.nonce);
	  assert.ok(/[0-9a-f]{48}/.exec(response.body.nonce));

	  done();
	});
      });

      describe('with inferred cabinet', function() {

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
	  assert.ok(/[0-9a-f]{64}/.exec(response.body.ciphertext));

	  assert.ok(response.body.nonce);
	  assert.ok(/[0-9a-f]{48}/.exec(response.body.nonce));

	  done();
	});
      });
    });

    describe('decryption', function() {

      // express middleware chain for decryption tests
      function decHandler(message, type) {
	return [
	  bc({ symmetric: { key: keys.secretkey } }),
	  function(req, res, next) {
	    try {
	      var [c, n] = req.bc(message, type);
	    } catch(ex) {
	      return next(ex);
	    }

	    req.c = c;
	    req.n = n;

	    next();
	  },
	  function(req, res, next) {
	    try {
	      var m = req.bc(req.c, req.n, type);
	    } catch(ex) {
	      return next(ex);
	    }

	    req.m = m;

	    next();
	  },
	  function(req, res) {
	    res.status(200).json({ plaintext: req.m });
	  },
	  function(err, req, res, next) {
	    res.status(400).json({ error: err.message });
	  }
	];
      };

      describe('of ciphertext constructed with string input', function() {

	var response;
	var plaintext = 'thisisatestplaintext';

	before(function(done) {
	  var handler = decHandler(plaintext, 'sym');

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

	  assert.ok(response.body.plaintext);
	  assert.equal(response.body.plaintext, plaintext);

	  done();
	});
      });

      describe('of ciphertext constructed with object input', function() {

	var response;
	var plaintext = { thisis: 'atestobject', withinteger: 123, and: { sub: 'objects' } };

	before(function(done) {
	  var handler = decHandler(plaintext, 'sym');

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

	  assert.ok(response.body.plaintext);
	  assert.equal(response.body.plaintext, JSON.stringify(plaintext)); // TODO: compare objects properly

	  done();
	});
      });

      describe('with inferred cabinet', function() {

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

	it('should return ciphertext and nonce', function(done) {
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
});
