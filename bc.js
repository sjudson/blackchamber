const libsodium = require('libsodium-wrappers');
const sodium    = require('libsodium');


/**
 * format
 *
 * format ciphertexts
 *
 * @param {String} ciphertext
 * @param {String} nonce
 * @api private
 *
 */
function format(ciphertext, nonce) {
  return ciphertext + '*' + nonce;
}


/**
 * parse
 *
 * parse ciphertexts
 *
 * @param {Object|String} input
 * @api private
 *
 */
function parse(input) {
  if (typeof input !== 'string') { return [ input, null ]; }

  var match = /([0-9a-f]+)\*([0-9a-f]{48})/.exec(input);
  if (!match) { return [ input, null ]; }

  return [ match[1], match[2] ];
}


/**
 * sinit
 *
 * initialize the symmetric cabinet
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
    return format(c, nout);
  }


  function dec(c, n) {
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
 * initialize the asymmetric cabinet
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
    return format(c, nout);
  }


  function dec(c, n) {
    var cin = libsodium.from_hex(c);
    var nin = libsodium.from_hex(n);

    var m = libsodium.crypto_box_open_easy(cin, nin, pk, sk, 'text');
    return m;
  }


  return [enc, dec];
}


/**
 * bc
 *
 * The main function, configures the cabinet and returns
 * the middleware that adds it to the express req object.
 *
 * @param {String} name
 * @param {Object} config
 * @api public
 *
 */
function bc(name, config) {
  if (typeof name === 'object') {
    config = name;
    name = undefined;
  }
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

  const direct = (cabinets.length === 1);


  /**
   * select
   *
   * select the cabinet to be used
   * for the cryptographic operation
   *
   * @param {String} specified
   * @api private
   *
   */
  function select(specified) {
    // infer the type if in direct mode
    type = specified || (direct && cabinets[0]);

    if (!type || ['sym', 'asy'].indexOf(type) === -1) {
      throw new Error('Please specify \'sym\' (symmetric) or \'asy\' (asymmetric) as the type.');
    }

    return type;
  }


  /**
   * encrypt
   *
   * encrypt a message using the denoted cabinet
   *
   * @param {Object|String} arg
   * @api public
   *
   */
  function encrypt(arg) {
    var type, message;

    function _encrypt(message) {
      // handle invalid arguments
      if (!message) {
	throw new Error('Unable to operate on an empty message.');
      }

      // if message is an object, stringify it
      if (typeof message === 'object') {
	message = JSON.stringify(message);
      }

      // prepare and launch the cryptographic operation
      var launch = registry[type];
      if (!launch) { throw new Error('Cabinet not initialized for type ' + type + '.'); }

      return launch['e'](message);
    }

    if (direct) {
      type = select(); // infer type
      message = arg;

      return _encrypt(message);
    } else {
      type = select(arg); // send argument as type

      return _encrypt;
    }
  }


  /**
   * decrypt
   *
   * decrypt a message using the denoted cabinet
   *
   * @param {String} arg
   * @param {String} opt
   * @api public
   *
   */
  function decrypt(arg, opt) {
    var type, message, nonce;

    function _decrypt(message, nonce) {
      if (!nonce) { [message, nonce] = parse(message); }

      if (!message) {
	throw new Error('Unable to operate on an empty message.');
      }

      if (!nonce) {
	throw new Error('Unable to decrypt without nonce.');
      }

      // prepare and launch the cryptographic operation
      var launch = registry[type];
      if (!launch) { throw new Error('Cabinet not initialized for type ' + type + '.'); }

      return launch['d'](message, nonce);
    }

    if (direct) {
      type = select(); // infer type

      return _decrypt(arg, opt);
    } else {
      type = select(arg); // send argument as type

      return _decrypt;
    }
  }


  const cabinetNoir = { direct: direct, encrypt: encrypt, decrypt: decrypt };

  return function(req, res, next) {
    if (name) {
      req[name] = cabinetNoir;
    } else {
      req.bc = cabinetNoir;
    }

    next();
  };

}


exports = module.exports = bc;

exports.symkg = () => {
  return { key: libsodium.crypto_secretbox_keygen('hex'), keyType: 'chacha20poly1305' };
};

exports.asykg = () => {
  return libsodium.crypto_box_keypair('hex');
};
