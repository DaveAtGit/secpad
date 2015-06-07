/**
 * Wrapper around sodium.js (https://github.com/jedisct1/libsodium.js) to
 * work easily with this altered etherpad.
 *
 * Interface/API:
 *
 * publickey():
 *		Returns the public key for the current session. If no key
 *		exists, the keypair will be generated.
 * prepare_symmkey(padId, recipient_pk):
 *		Encrypts the symmetrical key for the given pad, so the
 *		recipient (and only him/her) can use it.
 * store_symmkey(padId, encrypted_key):
 *		Stores the given encrypted symmetrical key for the given
 *		pad.
 * encrypt(padId, msg):
 *		Encrypts the given message for the required pad.
 * decrypt(padId, cypher):
 *		Decrypts the given cypher of the pad to clear-text.
 *
 * Additionally, keys are generated, if necessary. So there is no
 * call to any 'init'-function required.
 *
 * TODO this API might change, regarding the use of padId
 */
var sodium = require('./libsodium/libsodium-wrappers');

/* Would this whole import/require thing work, as expected,
 * it would be rather safe to store the keys in variables here.
 * But as it does not seem to be that easy (ace uses some weird
 * iframes), we have to use some kind of singleton-scheme. The
 * drawback: the global window can be accessed by anyone on the
 * clientside.
 */

if (typeof window == "undefined") {
	// There is still Changeset-usage on server-side. Even though
	// that should be deleted, this is a faster workaround...
	console.log(":: window is undefined");
	var global = {};
} else {
	console.log(":: window is defined");
	var global = window.top;
}

/* asymmetric keys */
var get_keys = function() {
	if (!global._keys) {
		var trpl = sodium.crypto_box_keypair();
		console.log(":: Created keypair");
		global._keys = { pk: sodium.to_base64(trpl.publicKey), sk: sodium.to_base64(trpl.privateKey)};
	}
	return global._keys;
};
exports.publickey = function() {
	return get_keys().pk;
};

/* symmetric keys */
var _create_symkeys_var = function() {
	if (!global._symkeys) {
		console.log(" : _symkeys not existent");
		global._symkeys = {};
	}
};
var get_symmetric_key = function(padId) {
	// TODO don't reuse nonce...
	// console.log(":: Asking for symmetric key");
	padId = _get_pad(padId);
	_create_symkeys_var();
	if (!(padId in global._symkeys)) {
		// a new key has to be created.
		// console.log(" : NEW");
		var nonce = sodium.to_base64(sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES));
		var key = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
		global._symkeys[padId] = { key: encrypt_asymmetrical(key, get_keys().pk), nonce: nonce };
	}
	//console.log(" : symkeys:");
	//console.log(global._symkeys);
	return global._symkeys[padId];
};

/* pad */
var _get_pad = function(padId) {
	if (padId != null)
		global._pad = padId;
	return global._pad;
};

/* "The nonce doesn't have to be confidential[...]"
 * https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html
 */

/* crypto_box_seal
 * https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html
 *
 * Process:
 * >> encrypt:
 * - decrypt own symmetrical key
 * - anonymously encrypt symm-key for other party
 *   - the pk might be encoded as base64
 *   - the symmkey will be encoded as base64
 * - send
 * << decrypt:
 * - receive
 * - decrypt for usage
 * - not necessary to re-encrypt, as it is only decryptable by this user
 */

var encrypt_asymmetrical = function(msg, publicKey) {
	//console.log("> Encrypting asymmetrical.");
	return sodium.crypto_box_seal(msg, sodium.from_base64(publicKey), "base64")
};
var decrypt_asymmetrical = function(msg) {
	//console.log("> Decrypting asymmetrical.");
	var _k = get_keys();
	return sodium.crypto_box_seal_open(sodium.from_base64(msg),
			sodium.from_base64(_k.pk), sodium.from_base64(_k.sk));
};

exports.prepare_symmkey = function(padId, recipient_pk) {
	if (recipient_pk === undefined) {
		recipient_pk = padId;
		padId = null;
	}
	padId = _get_pad(padId);
	console.log("> Preparing symmetrical key of pad '"+padId+"'.");

	return {key: encrypt_asymmetrical(decrypt_asymmetrical(get_symmetric_key(padId).key), recipient_pk),
			nonce: get_symmetric_key(padId).nonce };
};
exports.store_symmkey = function(padId, encrypted_key) {
	if (encrypted_key === undefined) {
		encrypted_key = padId;
		padId = null;
	}
	padId = _get_pad(padId);
	console.log("> Storing symmetrical key (encrypted) of pad '"+padId+"'.");

	_create_symkeys_var();
	// if (padId in global._symkeys) {
	// 	throw {name: "KeyExistentError", msg: "There does already a key exist for this pad."};
	// }
	global._symkeys[padId] = encrypted_key;
};

// TODO maybe work with latest used padId?!
exports.encrypt = function (padId, msg) {
	if (msg === undefined) {
		msg = padId;
		padId = null;
	}
	padId = _get_pad(padId);
	console.log("> Encrypting for pad '"+padId+"'.");

	var sk = get_symmetric_key(padId);
	return sodium.crypto_secretbox_easy(msg,
			sodium.from_base64(sk.nonce), decrypt_asymmetrical(sk.key),
			"base64");
};

exports.decrypt = function (padId, cypher) {
	if (cypher === undefined) {
		cypher = padId;
		padId = null;
	}
	padId = _get_pad(padId);
	console.log("> Decrypting for pad '"+padId+"'.");

	var sk = get_symmetric_key(padId);
	return sodium.crypto_secretbox_open_easy(sodium.from_base64(cypher),
			sodium.from_base64(sk.nonce), decrypt_asymmetrical(sk.key),
			"text");
};
