const MASTER_SECRET = Buffer.from("seeding", "utf8");
const assert = require("assert");
const crypto = require("crypto");
const bs58check = require("bs58check");
const secp256k1 = require("secp256k1");
const HARDENED_OFFSET = 0x80000000;

const deriveChild = (index, privateKey) => {
  var isHardened = index >= HARDENED_OFFSET;
  var indexBuffer = Buffer.allocUnsafe(4);
  indexBuffer.writeUInt32BE(index, 0);

  let data;

  if (isHardened) {
    // Hardened child
    // assert(this.privateKey, "Could not derive hardened child key");

    let pk = privateKey;
    // let zb = Buffer.alloc(1, 0);
    // pk = Buffer.concat([zb, pk]);

    // data = 0x00 || ser256(kpar) || ser32(index)
    // data = Buffer.concat([pk, indexBuffer]);
    // console.log(data);
  } else {
    // Normal child
    // data = serP(point(kpar)) || ser32(index)
    //      = serP(Kpar) || ser32(index)
    data = Buffer.concat([publicKey, indexBuffer]);
  }

  var I = crypto.createHmac("sha512", this.chainCode).update(data).digest();
  var IL = I.slice(0, 32);
  var IR = I.slice(32);

  var hd;

  // Private parent key -> private child key
  if (privateKey) {
    // ki = parse256(IL) + kpar (mod n)
    try {
      hd.privateKey = secp256k1.privateKeyTweakAdd(Buffer.from(privateKey), IL);
      // throw if IL >= n || (privateKey + IL) === 0
    } catch (err) {
      // In case parse256(IL) >= n or ki == 0, one should proceed with the next value for i
      return this.deriveChild(index + 1);
    }
    // Public parent key -> public child key
  } else {
    // Ki = point(parse256(IL)) + Kpar
    //    = G*IL + Kpar
    try {
      hd.publicKey = secp256k1.publicKeyTweakAdd(
        Buffer.from(publicKey),
        IL,
        true
      );
      // throw if IL >= n || (g**IL + publicKey) is infinity
    } catch (err) {
      // In case parse256(IL) >= n or Ki is the point at infinity, one should proceed with the next value for i
      return this.deriveChild(index + 1);
    }
  }

  hd.chainCode = IR;
  hd.depth = this.depth + 1;
  hd.parentFingerprint = this.fingerprint; // .readUInt32BE(0)
  hd.index = index;

  return hd;
};

const driveFn = (path, privateKey) => {
  if (path === "m" || path === "M" || path === "m'" || path === "M'") {
    return this;
  }

  var entries = path.split("/");
  let hdKey = this.privateKey;
  console.log(hdKey);
  entries.forEach(function (entry, idx) {
    if (idx === 0) {
      assert(/^[mM]{1}/.test(entry), 'Path must start with "m" or "M"');
      return;
    }

    let childIndex = parseInt(entry, 10); // & (HARDENED_OFFSET - 1)
    childIndex += HARDENED_OFFSET;
  });
  hdKey = Buffer.from(secp256k1.publicKeyCreate(privateKey, true));

  return hdKey;
};

exports.fromMasterSeed = (seedBuffer) => {
  const I = crypto
    .createHmac("sha512", MASTER_SECRET)
    .update(seedBuffer)
    .digest();
  const IL = I.slice(0, 32);
  const IR = I.slice(32);
  const hdKey = {
    chainCode: IR,
    privateKey: IL,
    drive: driveFn,
  };
  // hdKey[chainCode] = IR;
  // hdKey[privateKey] = IL;
  // console.log(hdKey);
  return hdKey;
};
