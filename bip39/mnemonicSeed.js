const wordList = require("../WordList/english.json");
const INVALID_ENTROPY = "Invalid entropy";
const randomBytes = require("randombytes");
const createHash = require("create-hash");
const unorm = require("unorm");
const pbkdf2 = require("pbkdf2");
// utils
const padding = (str, padString, length) => {
  while (str.length < length) {
    str = padString + str;
  }
  return str;
};

const bytesToBinary = (bytes) => {
  return bytes.map((x) => padding(x.toString(2), "0", 8)).join("");
};

// Use unorm until String.prototype.normalize gets better browser support
const salt = (password) => "mnemonic" + (unorm.nfkd(password) || "");

const checksumBits = (entropyBuffer) => {
  const ENT = entropyBuffer.length * 8;
  const CS = ENT / 32;
  const hash = createHash("sha256").update(entropyBuffer).digest();
  // console.log(hash);

  return bytesToBinary([].slice.call(hash)).slice(0, CS);
};

const entropyToMnemonic = (entropy, wordList) => {
  wordList = wordList || DEFAULT_WORDLIST;

  const entropyBuffer = Buffer.from(entropy, "hex");
  const entropyBits = bytesToBinary([].slice.call(entropyBuffer));
  const checksum = checksumBits(entropyBuffer);

  const bits = entropyBits + checksum;
  const chunks = bits.match(/(.{1,11})/g);

  const words = chunks.map(function (binary) {
    const index = parseInt(binary, 2);

    return wordList[index];
  });

  return words.join(" ");
};

exports.generateMnemonic = (wordList, strength, rng) => {
  strength = strength || 128;
  console.log(strength);
  if (strength % 32 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }
  rng = rng || randomBytes;
  return entropyToMnemonic(rng(strength / 8), wordList);
};

const mnemonicToSeedBuffer = (mnemonic, password) => {
  const mnemonicBuffer = Buffer.from(mnemonic, "utf8");
  const saltBuffer = Buffer.from(salt(password), "utf8");

  return pbkdf2.pbkdf2Sync(mnemonicBuffer, saltBuffer, 2048, 64, "sha512");
};

exports.mnemonicToSeed = (mnemonic) => {
  return mnemonicToSeedBuffer(mnemonic).toString("hex");
};
