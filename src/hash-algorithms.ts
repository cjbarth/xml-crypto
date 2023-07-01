import * as crypto from "crypto";
import { HashAlgorithm } from "./types";

class Sha1 implements HashAlgorithm {
  getHash: (xml: any) => string;
  getAlgorithmName: () => string;

  constructor() {
    this.getHash = function (xml) {
      const shasum = crypto.createHash("sha1");
      shasum.update(xml, "utf8");
      const res = shasum.digest("base64");
      return res;
    };

    this.getAlgorithmName = function () {
      return "http://www.w3.org/2000/09/xmldsig#sha1";
    };
  }
}

class Sha256 implements HashAlgorithm {
  getHash: (xml: any) => string;
  getAlgorithmName: () => string;
  constructor() {
    this.getHash = function (xml) {
      const shasum = crypto.createHash("sha256");
      shasum.update(xml, "utf8");
      const res = shasum.digest("base64");
      return res;
    };

    this.getAlgorithmName = function () {
      return "http://www.w3.org/2001/04/xmlenc#sha256";
    };
  }
}

class Sha512 implements HashAlgorithm {
  getHash: (xml: any) => string;
  getAlgorithmName: () => string;
  constructor() {
    this.getHash = function (xml) {
      const shasum = crypto.createHash("sha512");
      shasum.update(xml, "utf8");
      const res = shasum.digest("base64");
      return res;
    };

    this.getAlgorithmName = function () {
      return "http://www.w3.org/2001/04/xmlenc#sha512";
    };
  }
}

module.exports = {
  Sha1,
  Sha256,
  Sha512,
};
