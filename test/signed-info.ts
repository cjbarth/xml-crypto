import * as xpath from "xpath";
import * as xmldom from "@xmldom/xmldom";
import * as crypto from "crypto";
import * as isDomNode from "@xmldom/is-dom-node";
import { SignedXml, findAncestorNs, type CanonicalizationAlgorithmType } from "../src/index";

export function signSignedInfoAgain(
  xml: string,
  canonicalizationAlgorithm: CanonicalizationAlgorithmType,
  privateKey: crypto.KeyLike,
): string {
  const doc = new xmldom.DOMParser().parseFromString(xml);
  const signedInfo = xpath.select1("//*[local-name(.)='SignedInfo']", doc);
  isDomNode.assertIsNodeLike(signedInfo);
  const canonSignedInfo = new SignedXml().getCanonXml([canonicalizationAlgorithm], signedInfo, {
    ancestorNamespaces: findAncestorNs(doc, "//*[local-name(.)='SignedInfo']"),
  });
  const signatureValue = crypto
    .createSign("RSA-SHA256")
    .update(canonSignedInfo)
    .sign(privateKey, "base64");
  return xml.replace(/<SignatureValue>[^<]*/, `<SignatureValue>${signatureValue}`);
}
