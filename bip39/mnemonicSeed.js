const INVALID_ENTROPY = "Invalid entropy";
const randomBytes = require("randombytes");
const createHash = require("create-hash");
const unorm = require("unorm");
const pbkdf2 = require("pbkdf2");

// will add padString if the length of str is less than length.
// newStr = str + (length-str.length) * "PadString"
const padding = (str, padString, length) => {
  while (str.length < length) {
    str = padString + str;
  }
  return str;
};

// UNORM is used to make the string in a unsigned normalized integer.
// UNORM will make salt more complex and unpredictable.
const salt = (password) => "mnemonic" + (unorm.nfkd(password) || "");

/**
 *
 * @param {bytes} bytes which need to be converted to binary.
 * @returns binary representation of 16bytes(128bits)
 */

// padding is done to maintain the length(8) of the binary string.
// if the string of binary number is less than 8 length then it will add
// zero("0") in the last to make length=8.
const bytesToBinary = (bytes) => {
  return bytes.map((x) => padding(x.toString(2), "0", 8)).join("");
};

/**
 * @param {*} entropyBuffer
 * @returns binary representation of sha256 hash for first 4 bit from entropyBuffer.
 */
const checksumBits = (entropyBuffer) => {
  // convert the length to bit length.
  const ENT = entropyBuffer.length * 8;

  // 4 bits from the total length.
  const CS = ENT / 32;
  // take sha256 hash of entropyBuffer
  const hash = createHash("sha256").update(entropyBuffer).digest();

  // slice first 4 bits and return it in binary.
  return bytesToBinary([].slice.call(hash)).slice(0, CS);
};

/**
 *
 * @param {Bytes} entropy - Randomnes
 * @param {ARRAY} wordList - Array of 2048 words.
 * @returns {String} words - Return 12 word length string.
 */
const entropyToMnemonic = (entropy, wordList) => {
  // entropyBuffer will create a buffer of size(entropy.length)
  // take the hex conversion of random number generation.
  const entropyBuffer = Buffer.from(entropy, "hex");

  // convert bytes to binary.
  const entropyBits = bytesToBinary([].slice.call(entropyBuffer));

  // we need 11 bits to represent 2048 words (2^11).
  // so (128 bits from entropy + 4 bits from checksum) = 12*11;
  // hence there will be 11 segments of 12 bits each.
  const checksum = checksumBits(entropyBuffer);

  //
  const bits = entropyBits + checksum; // total no of bits(132) to represent

  // split the bits into 12 equal portion with each portion = 11 bits.
  const chunks = bits.match(/(.{1,11})/g);

  // every portion in chunks will represent a number in 11 bits format.

  // words will be an array of words from wordList.
  const words = chunks.map(function (binary) {
    const index = parseInt(binary, 2);
    return wordList[index];
  });

  return words.join(" ");
};

/**
 *
 * @param {Array} wordList (Array of 2048 words)
 * @param {Number} strength (The length of random bits needed)
 * @returns {String} mnemonic (The )
 */
exports.generateMnemonic = (wordList, strength) => {
  //The length of random bits needed
  strength = strength || 128;

  // If strength is not multiple of 32 we will not consider strength to be valid entropy strength.
  if (strength % 32 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }
  // convert the randomness to Mnemonic.
  return entropyToMnemonic(randomBytes(strength / 8), wordList);
};

/**
 *
 * @param {string} mnemonic - string of words.
 * @param {*} password - optional user-supplied passphrase string.
 * @returns - seed of mnemonic and password.
 */
const mnemonicToSeedBuffer = (mnemonic, password) => {
  const mnemonicBuffer = Buffer.from(mnemonic, "utf8");

  // The purpose of a salt in a key-stretching function(pbkdf2) is to
  // make it difficult to build a lookup table enabling a
  // brute-force attack eq: rainbow table.
  const saltBuffer = Buffer.from(salt(password), "utf8");

  // The total no of hash iteration needed to apply before giving the output.
  const iterations = 2048;
  // the total length of Output key
  const keyLen = 64;

  //The pdkdf2 function, with its 2048 rounds of hashing,
  // is a very effective protection against brute-force attacks against the
  // mnemonic or the passphrase.
  // It makes it extremely costly (in computation) to try more than a few
  // thousand passphrase and
  // mnemonic combinations, while the number of possible derived seeds is
  // vast (2^512).

  // the pdkdf2 function applies a pseudo random function such as
  // HMAC(hash-based message authentication)
  // by this key stretching function password cracking is more difficult.
  return pbkdf2.pbkdf2Sync(
    mnemonicBuffer,
    saltBuffer,
    iterations,
    keyLen,
    "sha512"
  );
};

exports.mnemonicToSeed = (mnemonic) => {
  return mnemonicToSeedBuffer(mnemonic).toString("hex");
};
