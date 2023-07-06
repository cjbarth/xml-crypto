const fs = require("fs");
const Utils = require("../lib/utils").Utils;
const expect = require("chai").expect;

describe("Utils tests", function () {
  describe("derToPem", function () {
    it("will return a normalized PEM format when given an non-normalized PEM format", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const pemAsArray = normalizedPem.trim().split("\n");
      const base64String = pemAsArray.slice(1, -1).join("");
      const nonNormalizedPem =
        pemAsArray[0] + "\n" + base64String + "\n" + pemAsArray[pemAsArray.length - 1];

      expect(Utils.derToPem(nonNormalizedPem)).to.equal(normalizedPem);
    });

    it("will return a normalized PEM format when given a base64 string", function () {
      const normalizedPem = fs.readFileSync("./test/static/client_public.pem", "latin1");
      const pemAsArray = normalizedPem.trim().split("\n");
      const base64String = pemAsArray.slice(1, -1).join("");

      expect(Utils.derToPem(base64String, "CERTIFICATE")).to.equal(normalizedPem);
    });

    it("will throw if the format is neither PEM nor DER", function () {
      expect(() => Utils.derToPem("not a pem")).to.throw();
    });
  });
});
