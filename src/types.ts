// Type definitions for @node-saml/xml-crypto
// Project: https://github.com/node-saml/xml-crypto#readme
// Original definitions by: Eric Heikes <https://github.com/eheikes>
//                          Max Chehab <https://github.com/maxchehab>

/// <reference types="node" />

import { SelectedValue } from "xpath";
import * as crypto from "crypto";
import { SignedXml } from "./signed-xml";

export type CanonicalizationAlgorithmType =
  | "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
  | "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
  | "http://www.w3.org/2001/10/xml-exc-c14n#"
  | "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

export type CanonicalizationOrTransformAlgorithmType =
  | CanonicalizationAlgorithmType
  | "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
  | string;

export type HashAlgorithmType =
  | "http://www.w3.org/2000/09/xmldsig#sha1"
  | "http://www.w3.org/2001/04/xmlenc#sha256"
  | "http://www.w3.org/2001/04/xmlenc#sha512"
  | string;

export type SignatureAlgorithmType =
  | "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
  | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
  | "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
  | string;

/**
 * Options for the SignedXml constructor.
 */
export type SignedXmlOptions = {
  idMode?: "wssecurity";
  idAttribute?: string;
  privateKey?: crypto.KeyLike;
  publicCert?: crypto.KeyLike;
  signatureAlgorithm?: SignatureAlgorithmType;
  canonicalizationAlgorithm?: CanonicalizationAlgorithmType;
  inclusiveNamespacesPrefixList?: string;
  implicitTransforms?: ReadonlyArray<CanonicalizationOrTransformAlgorithmType>;
  keyInfoAttributes?: Record<string, string>;
  getKeyInfoContent?(args?: GetKeyInfoContentArgs): string | null;
  getCertFromKeyInfo?(keyInfo: string): string | null;
};

export type CanonicalizationOrTransformationAlgorithmProcessOptions = {
  defaultNs?: string;
  defaultForPrefix?: {};
  ancestorNamespaces?: [];
  signatureNode: Node;
};

/**
 * Options for the computeSignature method.
 *
 *   - `prefix` {String} Adds a prefix for the generated signature tags
 * - `attrs` {Object} A hash of attributes and values `attrName: value` to add to the signature root node
 * - `location` {{ reference: String, action: String }}
 * - `existingPrefixes` {Object} A hash of prefixes and namespaces `prefix: namespace` already in the xml
 *   An object with a `reference` key which should
 *   contain a XPath expression, an `action` key which
 *   should contain one of the following values:
 *   `append`, `prepend`, `before`, `after`
 */
export type ComputeSignatureOptions = {
  prefix?: string;
  attrs?: { [attrName: string]: string };
  location?: {
    reference?: string;
    action?: "append" | "prepend" | "before" | "after";
  };
  existingPrefixes?: { [prefix: string]: string };
};

/**
 * Callback signature for the {@link SignedXml#computeSignature} method.
 */
export type ComputeSignatureCallback = (error: Error | null, signature: SignedXml | null) => void;

/**
 * Represents a reference node for XML digital signature.
 */
export interface Reference {
  // The XPath expression that selects the data to be signed.
  xpath: string;

  // Optional. An array of transforms to be applied to the data before signing.
  transforms?: ReadonlyArray<CanonicalizationOrTransformAlgorithmType>;

  // Optional. The algorithm used to calculate the digest value of the data.
  digestAlgorithm?: HashAlgorithmType;

  // Optional. The URI that identifies the data to be signed.
  uri?: string;

  // Optional. The digest value of the referenced data.
  digestValue?: string;

  // Optional. A list of namespace prefixes to be treated as "inclusive" during canonicalization.
  inclusiveNamespacesPrefixList?: string;

  // Optional. Indicates whether the URI is empty.
  isEmptyUri?: boolean;
}

/** Implement this to create a new CanonicalizationOrTransformationAlgorithm */
export interface CanonicalizationOrTransformationAlgorithm {
  process(node: Node, options: CanonicalizationOrTransformationAlgorithmProcessOptions): Node;

  getAlgorithmName(): CanonicalizationOrTransformAlgorithmType;
}

/** Implement this to create a new HashAlgorithm */
export interface HashAlgorithm {
  getAlgorithmName(): HashAlgorithmType;

  getHash(xml: string): string;
}

/** Implement this to create a new SignatureAlgorithm */
export interface SignatureAlgorithm {
  /**
   * Sign the given string using the given key
   */
  getSignature(
    signedInfo: crypto.BinaryLike,
    privateKey: crypto.KeyLike,
    callback?: (err: Error, signedInfo: string) => never
  ): string;

  /**
   * Verify the given signature of the given string using key
   *
   * @param key a public cert, public key, or private key can be passed here
   */
  verifySignature(
    material: string,
    key: crypto.KeyLike,
    signatureValue: string,
    callback?: (err: Error, verified: boolean) => never
  ): boolean;

  getAlgorithmName(): SignatureAlgorithmType;
}

/** Implement this to create a new TransformAlgorithm */
export interface TransformAlgorithm {
  getAlgorithmName(): CanonicalizationOrTransformAlgorithmType;

  process(node: Node): string;
}

/**
 * ### Sign
 * #### Properties
 * - {@link SignedXml#privateKey} [required]
 * - {@link SignedXml#publicCert} [optional]
 * - {@link SignedXml#signatureAlgorithm} [optional]
 * - {@link SignedXml#canonicalizationAlgorithm} [optional]
 * #### Api
 *  - {@link SignedXml#addReference}
 *  - {@link SignedXml#computeSignature}
 *  - {@link SignedXml#getSignedXml}
 *  - {@link SignedXml#getSignatureXml}
 *  - {@link SignedXml#getOriginalXmlWithIds}
 *
 * ### Verify
 * #### Properties
 * -  {@link SignedXml#publicCert} [optional]
 * #### Api
 *  - {@link SignedXml#loadSignature}
 *  - {@link SignedXml#checkSignature}
 *  - {@link SignedXml#validationErrors}
 */

/**
 * @param cert the certificate as a string or array of strings (see https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-X509Data)
 * @param prefix an optional namespace alias to be used for the generated XML
 */
export type GetKeyInfoContentArgs = {
  publicCert?: string | string[] | Buffer | null;
  prefix?: string | null;
};

export declare module utils {
  /**
   * @param pem The PEM-encoded base64 certificate to strip headers from
   */
  export function pemToDer(pem: string): string;

  /**
   * @param der The DER-encoded base64 certificate to add PEM headers too
   * @param pemLabel The label of the header and footer to add
   */
  export function derToPem(
    der: string,
    pemLabel: ["CERTIFICATE" | "PRIVATE KEY" | "RSA PUBLIC KEY"]
  ): string;

  /**
   * -----BEGIN [LABEL]-----
   * base64([DATA])
   * -----END [LABEL]-----
   *
   * Above is shown what PEM file looks like. As can be seen, base64 data
   * can be in single line or multiple lines.
   *
   * This function normalizes PEM presentation to;
   *  - contain PEM header and footer as they are given
   *  - normalize line endings to '\n'
   *  - normalize line length to maximum of 64 characters
   *  - ensure that 'preeb' has line ending '\n'
   *
   * With a couple of notes:
   *  - 'eol' is normalized to '\n'
   *
   * @param pem The PEM string to normalize to RFC7468 'stricttextualmsg' definition
   */
  export function normalizePem(pem: string): string;

  /**
   * PEM format has wide range of usages, but this library
   * is enforcing RFC7468 which focuses on PKIX, PKCS and CMS.
   *
   * https://www.rfc-editor.org/rfc/rfc7468
   *
   * PEM_FORMAT_REGEX is validating given PEM file against RFC7468 'stricttextualmsg' definition.
   *
   * With few exceptions;
   *  - 'posteb' MAY have 'eol', but it is not mandatory.
   *  - 'preeb' and 'posteb' lines are limited to 64 characters, but
   *     should not cause any issues in context of PKIX, PKCS and CMS.
   */
  export const EXTRACT_X509_CERTS: RegExp;
  export const PEM_FORMAT_REGEX: RegExp;
  export const BASE64_REGEX: RegExp;
}

export type ErrorBackCallback<T> =
  | ((err: Error, result?: never) => void)
  | ((err: null, result: T) => void);
