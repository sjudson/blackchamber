const assert = require('chai').assert;

const bc   = require('../bc');

describe('key generation', function() {

  describe('symmetric', function() {

    var skey;
    before(function(done) {
      skey = bc.symkg();
      done();
    });

    it('should return an object with the expected parameters', function(done) {
      assert.ok(typeof skey === 'object');

      var params = Object.keys(skey);
      assert.equal(params.length, 2);

      assert.ok(params.indexOf('key') > -1);
      assert.ok(params.indexOf('keyType') > -1);

      done();
    });

    it('should generate a secret key of hex-encoded length 64', function(done) {
      assert.ok(/[0-9a-f]{64}/.exec(skey.key));
      done();
    });

    it('should have a keyType of salsa20poly1305', function(done) {
      assert.equal(skey.keyType, 'salsa20poly1305');
      done();
    });
  });

  describe('asymmetric', function() {

    var akey;
    before(function(done) {
      akey = bc.asykg();
      done();
    });

    it('should return an object with the expected parameters', function(done) {
      assert.ok(typeof akey === 'object');

      var params = Object.keys(akey);
      assert.equal(params.length, 3);

      assert.ok(params.indexOf('privateKey') > -1);
      assert.ok(params.indexOf('publicKey') > -1);
      assert.ok(params.indexOf('keyType') > -1);

      done();
    });

    it('should generate keys of hex-encoded length 64', function(done) {
      assert.ok(/[0-9a-f]{64}/.exec(akey.privateKey));
      assert.ok(/[0-9a-f]{64}/.exec(akey.publicKey));
      done();
    });

    it('should have a keyType of curve25519', function(done) {
      assert.equal(akey.keyType, 'curve25519');
      done();
    });
  });
});
