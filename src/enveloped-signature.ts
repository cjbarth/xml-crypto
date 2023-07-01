const xpath = require("xpath");
import {
  CanonicalizationOrTransformationAlgorithm,
  CanonicalizationOrTransformationAlgorithmProcessOptions,
  CanonicalizationAlgorithmType,
  CanonicalizationOrTransformAlgorithmType,
} from "./types";
import { Utils } from "./utils";

class EnvelopedSignature implements CanonicalizationOrTransformationAlgorithm {
  includeComments: boolean = false;
  process(node: Node, options: CanonicalizationOrTransformationAlgorithmProcessOptions) {
    if (null == options.signatureNode) {
      const signature = xpath.select(
        "./*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
        node
      )[0];
      if (signature) {
        signature.parentNode.removeChild(signature);
      }
      return node;
    }
    const signatureNode = options.signatureNode;
    const expectedSignatureValue = xpath.select1(
      ".//*[local-name(.)='SignatureValue']/text()",
      signatureNode
    ).data;
    const signatures = xpath.select(
      ".//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      node
    );
    for (const nodeSignature of signatures) {
      const signatureValue = xpath.select1(
        ".//*[local-name(.)='SignatureValue']/text()",

        nodeSignature
      ).data;
      if (expectedSignatureValue === signatureValue) {
        nodeSignature.parentNode.removeChild(nodeSignature);
      }
    }
    return node;
  }

  getAlgorithmName(): CanonicalizationOrTransformAlgorithmType {
    return "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
  }
}

module.exports = {
  EnvelopedSignature,
};
