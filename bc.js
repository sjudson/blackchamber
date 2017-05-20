const libsodium = require('libsodium-wrappers');


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
  var k  = libsodium.from_hex(config.key);

  if (!k) { throw new Error('Symmetric key cabinet cannot be used without secret key.'); }

  function enc(m) {
    var n = libsodium.randombytes(libsodium._crypto_secretbox_noncebytes());
    var c = libsodium.crypto_secretbox_easy(m, n, k, 'hex');

    return [c, n];
  }

  function dec(c, n) {
    if (!n) { throw new Error('Nonce argument required for decryption.'); }

    var m = libsodium.crypto_secretbox_open_easy(c, n, k, 'hex');
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
  var sk = libsodium.from_hex(config.privateKey || config.secretKey || config.sk);
  var pk = libsodium.from_hex(config.publicKey  || config.pk);

  if (!sk) { throw new Error('Asymmetric key cabinet cannot be used without private (secret) key.'); }
  if (!pk) { throw new Error('Asymmetric key cabinet cannot be used without public key.'); }

  if (libsodium.crypto_scalarmult_base(sk, 'hex') === pk) {
    throw new Error('Invalid asymmetric key cabinet initialization: bound keypair.');
  }

  function enc(m) {
    var n = libsodium.randombytes(libsodium._crypto_box_noncebytes());
    var c = libsodium.crypto_box_easy(m, n, pk, sk, 'hex');

    return [c, n];
  }

  function dec(c, n) {
    if (!n) { throw new Error('Nonce argument required for decryption.'); }

    var m = libsodium.crypto_secretbox_open_easy(c, n, k, 'hex');
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
    var [asyE, asyD] = sinit(config.asymmetric);

    registry['asy'] = { e: asyE, d: asyD };
  }


  /**
   * infer
   *
   * Infer the type if only one registry.
   *
   * @param {Object} registry
   * @api private
   *
   */
  function infer(registry) {
    var cabinets = Object.keys(registry);
    if (cabinets.length === 1) { return cabinets.pop(); }

    return;
  }


  /**
   * cabinetNoir
   *
   * Translated as Black Chamber, the function exposed
   * at req.bc which may be used to encrypt or decrypt
   * blobs.
   *
   * @param {string|Uint8Array} message
   * @param {string|Uint8Array} nonce
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

    type = type || infer(registry);

    if (!type || ['sym', 'asy'].indexOf(type) === -1) {
      throw new Error('Please specify \'sym\' (symmetric) or \'asy\' (asymmetric) as the type.');
    }

    var base = registry[type];
    if (!base) { throw new Error('Cabinet not initialized for type ' + type + '.'); }

    // determine operation and launch
    var operation = (nonce) ? 'd' : 'e';

    if (operation === 'e') {
      base['e'](message);
    } else {  // operation === 'd'
      base['d'](message, nonce);
    }
  }


  return function(req, res, next) {
    req.bc = cabinetNoir;

    next();
  };

}


exports = module.exports = bc;

exports.symkg = () => {
  return { key: libsodium.crypto_secretbox_keygen('hex'), keyType: 'salsa20poly1305'};
};

exports.asykg = () => {
  return libsodium.crypto_box_keypair('hex');
};
