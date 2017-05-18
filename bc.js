const libsodium = require('libsodium');


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

  function enc(m) {
    var n = libsodium.randombytes(libsodium._crypto_secretbox_noncebytes());
    var c = libsodium.crypto_secretbox_easy(m, n, k);

    return [c, n];
  }

  function dec(c, n) {
    if (!n) { throw new Error('Nonce argument required for decryption.'); }
    
    var m = libsodium.crypto_secretbox_open_easy(c, n, k);
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
  if (!pk) { throw new Error('Asymmetric key cabinet cannot be used without public key.'); }

  function enc(m) {
    var n = libsodium.randombytes(libsodium._crypto_box_noncebytes());
    var c = libsodium.crypto_box_easy(m, n, pk, sk);

    return [c, n];
  }

  function dec(c, n) {
    if (!n) { throw new Error('Nonce argument required for decryption.'); }
    
    var m = libsodium.crypto_secretbox_open_easy(c, n, k);
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

  var [symE, symD] = sinit(config.symmetric);
  var [asyE, asyD] = ainit(config.asymmetric);

  var registry = {
    sym: {
      e: symE,
      d: symD
    },
    asy: {
      e: asyE,
      d: asyD
    }
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

    if (!type || ['sym', 'asy'].indexOf(type) === -1) {
      throw new Error('Please specify \'sym\' (symmetric) or \'asy\' (asymmetric) as the type.');
    }


    // determine operation and launch
    var operation = (nonce) ? 'd' : 'e';

    if (operation === 'e') {
      registry[type]['e'](message);
    } else {  // operation === 'd'
      registry[type]['d'](message, nonce);
    }
  }


  return function(req, res, next) {
    req.bc = cabinetNoir;

    next();
  };

}


module.exports = bc;
