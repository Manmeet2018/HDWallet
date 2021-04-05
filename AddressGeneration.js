const hdkey = require("hdkey");
const createHash = require("create-hash");
const bs58check = require("bs58check");
const wordList = require("./WordList/english.json");
const { generateMnemonic, mnemonicToSeed } = require("./bip39/mnemonicSeed");
const { fromMasterSeed } = require("./bip32/seedToRoot");

const mnemonic = generateMnemonic(wordList); //generates mnemonic string
console.log(mnemonic);
const seed = mnemonicToSeed(mnemonic); //creates seed buffer
console.log("Seed: " + seed);
// console.log("mnemonic: " + mnemonic);
const root = hdkey.fromMasterSeed(seed);
const masterPrivateKey = root.privateKey.toString("hex");
console.log("masterPrivateKey: " + masterPrivateKey);
const addrIndex = 0;
const addrNode = root.derive(`m/44'/0'/0'/0/${addrIndex}`);
console.log("addrNodePublicKey: " + addrNode._publicKey);

const step1 = addrNode._publicKey;
const step2 = createHash("sha256").update(step1).digest();
const step3 = createHash("rmd160").update(step2).digest();

const step4 = Buffer.allocUnsafe(21);
step4.writeUInt8(0x00, 0);
step3.copy(step4, 1); //step4 now holds the extended RIPMD-160 result
const step9 = bs58check.encode(step4);
console.log("Base58Check: " + step9);
