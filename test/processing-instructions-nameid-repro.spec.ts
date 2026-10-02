import { expect } from "chai";
import * as fs from "fs";
import * as xmldom from "@xmldom/xmldom";
import { SignedXml } from "../src/index";

describe("processing instructions in signed SAML assertions", function () {
  it("rejects a PI that changes the NameID seen in the received DOM", function () {
    const samlNs = "urn:oasis:names:tc:SAML:2.0:assertion";
    const dsNs = "http://www.w3.org/2000/09/xmldsig#";
    const exclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
    const signer = new SignedXml({
      privateKey: fs.readFileSync("./test/static/client.pem"),
      canonicalizationAlgorithm: exclusiveC14n,
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    });
    signer.addReference({
      xpath: "//*[local-name(.)='Assertion']",
      transforms: [`${dsNs}enveloped-signature`, exclusiveC14n],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    });
    signer.computeSignature(
      `<saml:Assertion xmlns:saml="${samlNs}" ID="_signed" Version="2.0" IssueInstant="2026-10-02T00:00:00Z">` +
        "<saml:Issuer>https://idp.example/</saml:Issuer>" +
        '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">' +
        "admin@victim.com.evil.com</saml:NameID></saml:Subject>" +
        "</saml:Assertion>",
    );

    const verify = (xml: string) => {
      const doc = new xmldom.DOMParser().parseFromString(xml);
      const signature = doc.getElementsByTagNameNS(dsNs, "Signature").item(0);
      if (signature === null) {
        throw new Error("Expected a signature in the received assertion");
      }
      const verifier = new SignedXml({
        publicCert: fs.readFileSync("./test/static/client_public.pem"),
      });
      verifier.loadSignature(signature);
      return verifier.checkSignature(xml);
    };

    const signedXml = signer.getSignedXml();
    expect(verify(signedXml)).to.be.true;

    const tamperedXml = signedXml.replace(
      "admin@victim.com.evil.com",
      "admin@victim.com<?x .evil.com?>",
    );
    expect(tamperedXml).to.not.equal(signedXml);
    const tamperedDoc = new xmldom.DOMParser().parseFromString(tamperedXml);
    const nameId = tamperedDoc.getElementsByTagNameNS(samlNs, "NameID").item(0);
    if (nameId === null) {
      throw new Error("Expected NameID in the received assertion");
    }
    expect(nameId.textContent).to.equal("admin@victim.com");
    expect(verify(tamperedXml)).to.be.false;
  });
});
