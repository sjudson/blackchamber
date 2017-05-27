const libsodium = require('libsodium-wrappers');
const sodium    = require('libsodium');


/**
 * sinit
 *
 * Initialize the symmetric cabinet.
 *
 * @param {Object} config
 * @api private
 *
 */
function sinit(config) {
  config = config || {};
  var k  = config.key;

  if (!k) { throw new Error('Symmetric key cabinet cannot be used without secret key.'); }
  k = libsodium.from_hex(k);


  function enc(m) {
    var n = libsodium.randombytes_buf(sodium._crypto_secretbox_noncebytes());
    var nout = libsodium.to_hex(n);

    var c = libsodium.crypto_secretbox_easy(m, n, k, 'hex');
    return [c, nout];
  }


  function dec(c, n) {
    if (!n) { throw new Error('Nonce argument required for decryption.'); }
    var cin = libsodium.from_hex(c);
    var nin = libsodium.from_hex(n);

    var m = libsodium.crypto_secretbox_open_easy(cin, nin, k, 'text');
    return m;
  }


  return [enc, dec];
}


/**
 * ainit
 *
 * Initialize the asymmetric cabinet.
 *
 * @param {Object} config
 * @api private
 *
 */
function ainit(config) {
  config = config || {};
  var sk = config.privateKey || config.secretKey || config.sk;
  var pk = config.publicKey  || config.pk;

  if (!sk) { throw new Error('Asymmetric key cabinet cannot be used without private (secret) key.'); }
  sk = libsodium.from_hex(sk);

  if (!pk) { throw new Error('Asymmetric key cabinet cannot be used without public key.'); }
  pk = libsodium.from_hex(pk);

  if (libsodium.compare(libsodium.crypto_scalarmult_base(sk), pk) === 0) {
    throw new Error('Invalid asymmetric key cabinet initialization: bound keypair.');
  }


  function enc(m) {
    var n = libsodium.randombytes_buf(sodium._crypto_box_noncebytes());
    var nout = libsodium.to_hex(n);

    var c = libsodium.crypto_box_easy(m, n, pk, sk, 'hex');
    return [c, nout];
  }


  function dec(c, n) {
    if (!n) { throw new Error('Nonce argument required for decryption.'); }
    var cin = libsodium.from_hex(c);
    var nin = libsodium.from_hex(n);

    var m = libsodium.crypto_secretbox_open_easy(cin, nin, k, 'text');
    return m;
  }


  return [enc, dec];
}


/**
 * bc
 *
 * The main function, configures the cabinet and returns
 * the middleware that adds it to the express req obj.
 *
 * @param {Object} config
 * @api public
 *
 */
function bc(config) {
  config = config || {};

  var registry = new Object();

  if (config.symmetric) {
    var [symE, symD] = sinit(config.symmetric);

    registry['sym'] = { e: symE, d: symD };
  }

  if (config.asymmetric) {
    var [asyE, asyD] = ainit(config.asymmetric);

    registry['asy'] = { e: asyE, d: asyD };
  }

  var cabinets = Object.keys(registry);
  if (cabinets.length < 1) { throw new Error('Configuration objects required for middleware.'); }


  /**
   * cabinetNoir
   *
   * Translated as Black Chamber, the function exposed
   * at req.bc which may be used to encrypt or decrypt
   * blobs.
   *
   * @param {object|string} message
   * @param {string} nonce
   * @param {string} type
   * @api private
   *
   */
  function cabinetNoir(message, nonce, type) {
    var arity = arguments.length;
    if (arity === 2) {
      type  = nonce;
      nonce = undefined;
    }

    // handle invalid arguments
    if (!message) {
      throw new Error('Unable to operate on an empty message.');
    }

    // if message is an object, stringify it
    if (typeof message === 'object') {
      message = JSON.stringify(message);
    }

    if (!type || ['sym', 'asy'].indexOf(type) === -1) {
      throw new Error('Please specify \'sym\' (symmetric) or \'asy\' (asymmetric) as the type.');
    }

    // prepare and launch the cryptographic operation
    var base = registry[type];
    if (!base) { throw new Error('Cabinet not initialized for type ' + type + '.'); }

    var operation = (nonce) ? 'd' : 'e';

    if (operation === 'e') {
      return base['e'](message);
    } else {  // operation === 'd'
      return base['d'](message, nonce);
    }
  }


  return function(req, res, next) {
    req.bc = cabinetNoir;

    next();
  };

}


exports = module.exports = bc;

exports.symkg = () => {
  return { key: libsodium.crypto_secretbox_keygen('hex'), keyType: 'salsa20poly1305' };
};

exports.asykg = () => {
  return libsodium.crypto_box_keypair('hex');
};
