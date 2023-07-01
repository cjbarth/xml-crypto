import * as crypto from "crypto";
import { SignatureAlgorithm } from "./types";

class RsaSha1 implements SignatureAlgorithm {
  getSignature = (signedInfo, privateKey, callback) => {
    const signer = crypto.createSign("RSA-SHA1");
    signer.update(signedInfo);
    const res = signer.sign(privateKey, "base64");
    if (callback) {
      callback(null, res);
    }
    return res;
  };

  verifySignature = (str, key, signatureValue, callback) => {
    const verifier = crypto.createVerify("RSA-SHA1");
    verifier.update(str);
    const res = verifier.verify(key, signatureValue, "base64");
    if (callback) {
      callback(null, res);
    }
    return res;
  };

  getAlgorithmName = () => {
    return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  };
}

class RsaSha256 implements SignatureAlgorithm {
  getSignature = (signedInfo, privateKey, callback) => {
    const signer = crypto.createSign("RSA-SHA256");
    signer.update(signedInfo);
    const res = signer.sign(privateKey, "base64");
    if (callback) {
      callback(null, res);
    }
    return res;
  };

  verifySignature = (str, key, signatureValue, callback) => {
    const verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(str);
    const res = verifier.verify(key, signatureValue, "base64");
    if (callback) {
      callback(null, res);
    }
    return res;
  };

  getAlgorithmName = () => {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  };
}

class RsaSha512 implements SignatureAlgorithm {
  getSignature = (signedInfo, privateKey, callback) => {
    const signer = crypto.createSign("RSA-SHA512");
    signer.update(signedInfo);
    const res = signer.sign(privateKey, "base64");
    if (callback) {
      callback(null, res);
    }
    return res;
  };

  verifySignature = (str, key, signatureValue, callback) => {
    const verifier = crypto.createVerify("RSA-SHA512");
    verifier.update(str);
    const res = verifier.verify(key, signatureValue, "base64");
    if (callback) {
      callback(null, res);
    }
    return res;
  };

  getAlgorithmName = () => {
    return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
  };
}

class HmacSha1 implements SignatureAlgorithm {
  verifySignature = (str, key, signatureValue, callback) => {
    const verifier = crypto.createHmac("SHA1", key);
    verifier.update(str);
    const res = verifier.digest("base64");

    if (callback) {
      callback(null, res === signatureValue);
    } else {
      return res === signatureValue;
    }
  };

  getAlgorithmName = () => {
    return "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
  };

  getSignature(signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string;
  getSignature(
    signedInfo: crypto.BinaryLike,
    privateKey: crypto.KeyLike,
    callback: (err: Error | null, signedInfo: string) => never
  ): never;
  getSignature(
    signedInfo: crypto.BinaryLike,
    privateKey: crypto.KeyLike,
    callback?: (err: Error | null, signedInfo: string) => never
  ): string | never {
    const signer = crypto.createHmac("SHA1", privateKey);
    signer.update(signedInfo);
    const res = signer.digest("base64");

    if (callback) {
      callback(null, res);
    }

    return res;
  }
}

export { RsaSha1, RsaSha256, RsaSha512, HmacSha1 };
