const assert = require('chai').assert;

const keys = require('./support/keys');
const bc   = require('../bc');

describe('configuration', function() {

  it('should export a unary function', function(done) {
    assert.equal(bc.length, 1);
    return done();
  });

  it('should error without configuration object', function(done) {
    var req = {};

    try {
      var middleware = bc();
    } catch(ex) {
      assert.equal(ex.message, 'Configuration objects required for middleware.');
      return done();
    }

  });

  describe('for symmetric cabinet', function() {

    it('should error without a key', function(done) {
      var req = {};

      try {
	var middleware = bc({ symmetric: { } });
      } catch(ex) {
	assert.equal(ex.message, 'Symmetric key cabinet cannot be used without secret key.');
	return done();
      }

    });

    it('should error with a non-hex encoded key', function(done) {
      var req = {};

      try {
	var middleware = bc({ symmetric: { key: 'nonbase64encodedkey' } });
      } catch(ex) {
	assert.equal(ex.message, 'The provided string doesn\'t look like hex data');
        return done();
      }

    });

    it('should work with a valid key', function(done) {
      var req = {};

      var middleware = bc({ symmetric: { key: keys.secretkey } });
      middleware(req, {}, () => {});

      assert.ok(req.bc);

      return done();
    });
  });

  describe('for asymmetric cabinet', function() {

    it('should error with no keys', function(done) {
      var req = {};

      try {
	var middleware = bc({ asymmetric: { } });
      } catch(ex) {
	assert.equal(ex.message, 'Asymmetric key cabinet cannot be used without private (secret) key.');
	return done();
      }

    });

    it('should error without a private key', function(done) {
      var req = {};

      try {
	var middleware = bc({ asymmetric: { publicKey: keys.r_publickey } });
      } catch(ex) {
	assert.equal(ex.message, 'Asymmetric key cabinet cannot be used without private (secret) key.');
	return done();
      }

    });

    it('should error with a non-hex encoded private key', function(done) {
      var req = {};

      try {
	var middleware = bc({ asymmetric: { privateKey: 'nonbase64encodedkey', publicKey: keys.r_publickey } });
      } catch(ex) {
	assert.equal(ex.message, 'The provided string doesn\'t look like hex data');
        return done();
      }

    });

    it('should error without a public key', function(done) {
      var req = {};

      try {
	var middleware = bc({ asymmetric: { privateKey: keys.s_privatekey } });
      } catch(ex) {
	assert.equal(ex.message, 'Asymmetric key cabinet cannot be used without public key.');
	return done();
      }

    });

    it('should error with a non-hex encoded public key', function(done) {
      var req = {};

      try {
	var middleware = bc({ asymmetric: { privateKey: keys.s_privatekey, publicKey: 'nonbase64encodedkey' } });
      } catch(ex) {
	assert.equal(ex.message, 'The provided string doesn\'t look like hex data');
	return done();
      }

    });

    it('should error with a bound keypair', function(done) {
      var req = {};

      try {
	var middleware = bc({ asymmetric: { privateKey: keys.s_privatekey, publicKey: keys.s_publickey } });
      } catch(ex) {
	assert.equal(ex.message, 'Invalid asymmetric key cabinet initialization: bound keypair.');
        return done();
      }

    });

    it('should work with a valid set of keys', function(done) {
      var req = {};

      var middleware = bc({ asymmetric: { privateKey: keys.s_privatekey, publicKey: keys.r_publickey } });
      middleware(req, {}, () => {});

      assert.ok(req.bc);

      return done();
    });

    it('should work with secretKey alias', function(done) {
      var req = {};

      var middleware = bc({ asymmetric: { secretKey: keys.s_privatekey, publicKey: keys.r_publickey } });
      middleware(req, {}, () => {});

      assert.ok(req.bc);

      return done();
    });

    it('should work with sk alias', function(done) {
      var req = {};

      var middleware = bc({ asymmetric: { sk: keys.s_privatekey, publicKey: keys.r_publickey } });
      middleware(req, {}, () => {});

      assert.ok(req.bc);

      return done();
    });

    it('should work with pk alias', function(done) {
      var req = {};

      var middleware = bc({ asymmetric: { privateKey: keys.s_privatekey, pk: keys.r_publickey } });
      middleware(req, {}, () => {});

      assert.ok(req.bc);

      return done();
    });
  });

  describe('for both', function() {

    it('should be simultaneously configurable', function(done) {
      var req = {};

      var middleware = bc({
	symmetric: { key: keys.secretkey },
	asymmetric: { privateKey: keys.s_privatekey, publicKey: keys.r_publickey }
      });
      middleware(req, {}, () => {});

      assert.ok(req.bc);

      return done();

    });
  });
});
