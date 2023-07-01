import * as crypto from "crypto";
import { SignatureAlgorithm } from "./types";

class RsaSha1 implements SignatureAlgorithm {
  getSignature: (signedInfo: any, privateKey: any, callback: any) => string;
  verifySignature: (str: any, key: any, signatureValue: any, callback: any) => boolean;
  getAlgorithmName: () => string;

  constructor() {
    /**
     * Sign the given string using the given key
     *
     */
    this.getSignature = function (signedInfo, privateKey, callback) {
      const signer = crypto.createSign("RSA-SHA1");
      signer.update(signedInfo);
      const res = signer.sign(privateKey, "base64");
      if (callback) {
        callback(null, res);
      }
      return res;
    };

    /**
     * Verify the given signature of the given string using key
     *
     */
    this.verifySignature = function (str, key, signatureValue, callback) {
      const verifier = crypto.createVerify("RSA-SHA1");
      verifier.update(str);
      const res = verifier.verify(key, signatureValue, "base64");
      if (callback) {
        callback(null, res);
      }
      return res;
    };

    this.getAlgorithmName = function () {
      return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    };
  }
}

class RsaSha256 implements SignatureAlgorithm{
  getSignature: (signedInfo: any, privateKey: any, callback: any) => string;
  verifySignature: (str: any, key: any, signatureValue: any, callback: any) => boolean;
  getAlgorithmName: () => string;

  constructor() {
    this.getSignature = function (signedInfo, privateKey, callback) {
      const signer = crypto.createSign("RSA-SHA256");
      signer.update(signedInfo);
      const res = signer.sign(privateKey, "base64");
      if (callback) {
        callback(null, res);
      }
      return res;
    };

    this.verifySignature = function (str, key, signatureValue, callback) {
      const verifier = crypto.createVerify("RSA-SHA256");
      verifier.update(str);
      const res = verifier.verify(key, signatureValue, "base64");
      if (callback) {
        callback(null, res);
      }
      return res;
    };

    this.getAlgorithmName = function () {
      return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    };
  }
}

class RsaSha512 implements SignatureAlgorithm {
  getSignature: (signedInfo: any, privateKey: any, callback: any) => string;
  verifySignature: (str: any, key: any, signatureValue: any, callback: any) => boolean;
  getAlgorithmName: () => string;

  constructor() {
    this.getSignature = function (signedInfo, privateKey, callback) {
      const signer = crypto.createSign("RSA-SHA512");
      signer.update(signedInfo);
      const res = signer.sign(privateKey, "base64");
      if (callback) {
        callback(null, res);
      }
      return res;
    };

    this.verifySignature = function (str, key, signatureValue, callback) {
      const verifier = crypto.createVerify("RSA-SHA512");
      verifier.update(str);
      const res = verifier.verify(key, signatureValue, "base64");
      if (callback) {
        callback(null, res);
      }
      return res;
    };

    this.getAlgorithmName = function () {
      return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    };
  }
}

class HmacSha1 implements SignatureAlgorithm{
  verifySignature: (str: any, key: any, signatureValue: any) => boolean;
  getAlgorithmName: () => string;
  getSignature: (signedInfo: any, privateKey: any) => string;

  constructor() {
    this.verifySignature = function (str, key, signatureValue) {
      const verifier = crypto.createHmac("SHA1", key);
      verifier.update(str);
      const res = verifier.digest("base64");
      return res === signatureValue;
    };

    this.getAlgorithmName = function () {
      return "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
    };

    this.getSignature = function (signedInfo, privateKey) {
      const verifier = crypto.createHmac("SHA1", privateKey);
      verifier.update(signedInfo);
      const res = verifier.digest("base64");
      return res;
    };
  }
}

module.exports = {
  RsaSha1,
  RsaSha256,
  RsaSha512,
  HmacSha1,
};
