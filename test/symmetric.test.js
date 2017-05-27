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
	      var c = req.bc(message, type);
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
	  assert.ok(/bc\*([0-9a-f]+)\*([0-9a-f]{48})/.exec(response.body.ciphertext));

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
	  assert.ok(/bc\*([0-9a-f]+)\*([0-9a-f]{48})/.exec(response.body.ciphertext));

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
	  assert.ok(/bc\*([0-9a-f]+)\*([0-9a-f]{48})/.exec(response.body.ciphertext));

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
	      var c = req.bc(message, type);
	    } catch(ex) {
	      return next(ex);
	    }

	    req.c = c;

	    next();
	  },
	  function(req, res, next) {
	    try {
	      var m = req.bc(req.c, type);
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
	  var handler = decHandler(plaintext, 'sym');

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
	  var handler = decHandler(plaintext, 'sym');

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
		var [c, n] = req.bc();
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
		var m = req.bc();
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
  });
});
