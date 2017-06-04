## blackchamber

Simple confidentiality and message integrity via NaCl as Express middleware. MIT Licensed.

#### Installation

```sh
$ npm i blackchamber
```

#### Use

The intent of blackchamber is to provide message confidentiality and integrity with the minimal configuration and greatest ease-of-use within Express applications. To accomplish this, it uses Dan Bernstein's [NaCl](https://nacl.cr.yp.to/) suite, implemented in [libsodium](https://download.libsodium.org/doc/) and exposed to Node by [libsodium.js](https://github.com/jedisct1/libsodium.js). More specifically, it employs the Salsa20-Poly1205 AEAD construction, with Diffie-Hellmann Exchange over Curve25519 as a key agreement scheme for its asymmetric mode. For more information, the linked pages on NaCl and libsodium are recommended sources. The library does not currently provide any mechanism for key management - as such, its recommended use is for securing communication between internal services or encryption of state information to be exposed over HTTP.

##### Key Generation

Although blackchamber does not provide key management, it does expose key generation wrappers for any desired use.

```js
const blackchamber = require('blackchamber');

var symkey = blackchamber.symkg();
// { key: 'd905d138cf964a8debf75321340d4301f90839bc20926e9e79ab415aa5e65bac', keyType: 'salsa20poly1305' }  

var asykey = blackchamber.asykg();
// { publicKey: '3e7f2e4680f56a59a48c091c723cf918f85d8090df65371cf6caaf141521ed62', privateKey:'c981761d12e0d616e092e2fd30cfc2e827ae025e6d039cb7dc51fbafb62873f9', keyType: 'curve25519' }  
```

##### Configuration

The API for blackchamber exposed by the library is used to configure a symmetric and/or asymmetric 'cabinet' to be employed for the cryptographic operations. Although this may be done directly (and dynamically) on a specific route, the more common usage will be to set it globally.

```js
const blackchamber = require('blackchamber');
const express = require('express');

const app = express();

app.use(blackchamber('crypto', { symmetric: { key: '3173a5188a421783a89b7f5910a57f42c830cb5bfe7c7174d1847655650fae4b' } }));
```

The first argument is optional, and specifies the name under which the functionality should be appended to the `req` object. So in the above example, the `encrypt` and `decrypt` functions will be available on `req.crypto`. If omitted, they are placed onto `req.bc`. The asymmetric cabinet is configured similarly, with a `privateKey` (alias `secretKey` or `sk`) and a `publicKey` (alias `pk`). Both symmetric and asymmetric cabinets may be configured at once, as well.

All keys must be hex encoded. It is of course recommended as well that they be properly secured, and not hardcoded or checked into version control.

##### Encryption

If only a symmetric or asymmetric cabinet is configured - but not both - then encrypting messages is straightforward.

```js
function(req, res, next) {
  var m = 'somemessage';
  
  try {
    var c = req.crypto.encrypt(m);
  } catch(ex) {
    return next(ex);
  }
  
  res.status(200).json({ ciphertext: c });
}
```

It is recommended that the message be a string. However, if an object is sent, then the library will attempt to use `JSON.stringify` on it. The ciphertext will have the format `([0-9a-f])*([0-9a-f]{48})`, where the star divides between the message and nonce components. Although they may be safely broken up, they will both be needed for the decryption process.

If multiple cabinets are configured simultaneously, then it is required to specify which one should be used. In such a case, the original function call will expose an internal function to actually handle the encryption.

```js
function(req, res, next) {
  var m = 'somemessage';
  
  try {
    var c = req.crypto.encrypt('sym')(m);
  } catch(ex) {
    return next(ex);
  }
  
  res.status(200).json({ ciphertext: c });
}
```

The caller must provide `sym` for the symmetric cabinet, and `asy` for the `asymmetric` one. Whether or not this indicator must be programmatically provided can be checked by `req.crypto.direct`. If `true`, then it is unneccesary.

##### Decryption

Decryption is provided nearly identically, with the distinction that the function takes two arguments, `message` and `nonce`. However, if you provide them as a single string joined with a star (matching the output of the encryption function) then it'll properly parse it for you. Both the `message` and `nonce` components of the ciphertext must be hex encoded.

```js
// together
function(req, res, next) {
  var c = '0b0f658b7d8498fdfcb051b8a2dee4416e317b589a0ec32d29c31f9856c8d2b49057c633*14e44349261e3bb87a61a100a493d7a78aa43b83b66d7483';
  
  try {
    var m = req.crypto.decrypt(c);
  } catch(ex) {
    return next(ex);
  }
  
  res.status(200).json({ plaintext: m });
}

// separated
function(req, res, next) {
  var c = '0b0f658b7d8498fdfcb051b8a2dee4416e317b589a0ec32d29c31f9856c8d2b49057c633';
  var n = '14e44349261e3bb87a61a100a493d7a78aa43b83b66d7483';
  
  try {
    var m = req.crypto.decrypt(c, n);
  } catch(ex) {
    return next(ex);
  }
  
  res.status(200).json({ plaintext: m });
}

```

Use with multiple cabinets is identical as in the Encryption example.

##### Incidentals

This library was written and is maintained by Samuel Judson. It is published under the MIT License. Pull requests and issues are welcome.
