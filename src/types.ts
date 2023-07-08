/* eslint-disable no-unused-vars */
// Type definitions for @node-saml/xml-crypto
// Project: https://github.com/node-saml/xml-crypto#readme
// Original definitions by: Eric Heikes <https://github.com/eheikes>
//                          Max Chehab <https://github.com/maxchehab>

/// <reference types="node" />

import * as crypto from "crypto";

export type ErrorFirstCallback<T> = (err: Error | null, result?: T) => void;

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
 * @param cert the certificate as a string or array of strings (see https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-X509Data)
 * @param prefix an optional namespace alias to be used for the generated XML
 */
export type GetKeyInfoContentArgs = {
  publicCert?: crypto.KeyLike;
  prefix?: string | null;
};

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

export type NamespacePrefix = {
  prefix: string;
  namespaceURI: string;
};

export type ProcessOptions = {
  defaultNs?: string;
  defaultNsForPrefix?: NamespacePrefix;
  ancestorNamespaces?: NamespacePrefix[];
};

export type RenderedNamespace = {
  rendered: string;
  newDefaultNs: string;
};

export type CanonicalizationOrTransformationAlgorithmProcessOptions = {
  defaultNs?: string;
  defaultForPrefix?: object;
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
 * Represents a reference node for XML digital signature.
 */
export interface Reference {
  // The XPath expression that selects the data to be signed.
  xpath: string | null;

  // Optional. An array of transforms to be applied to the data before signing.
  transforms?: ReadonlyArray<CanonicalizationOrTransformAlgorithmType>;

  // Optional. The algorithm used to calculate the digest value of the data.
  digestAlgorithm: HashAlgorithmType;

  // Optional. The URI that identifies the data to be signed.
  uri?: string;

  // Optional. The digest value of the referenced data.
  digestValue?: unknown;

  // Optional. A list of namespace prefixes to be treated as "inclusive" during canonicalization.
  inclusiveNamespacesPrefixList?: string;

  // Optional. Indicates whether the URI is empty.
  isEmptyUri?: boolean;
}

/** Implement this to create a new CanonicalizationOrTransformationAlgorithm */
export interface CanonicalizationOrTransformationAlgorithm {
  process(node: Node, options: CanonicalizationOrTransformationAlgorithmProcessOptions): Node;

  getAlgorithmName(): CanonicalizationOrTransformAlgorithmType;

  includeComments: boolean;
}

/** Implement this to create a new HashAlgorithm */
export interface HashAlgorithm {
  getAlgorithmName(): HashAlgorithmType;

  getHash(xml: string): string;
}

/** Extend this to create a new SignatureAlgorithm */
export interface SignatureAlgorithm {
  /**
   * Sign the given string using the given key
   */
  getSignature(signedInfo: crypto.BinaryLike, privateKey: crypto.KeyLike): string;
  getSignature(
    signedInfo: crypto.BinaryLike,
    privateKey: crypto.KeyLike,
    callback?: ErrorFirstCallback<string>
  ): void;
  /**
   * Verify the given signature of the given string using key
   *
   * @param key a public cert, public key, or private key can be passed here
   */
  verifySignature(material: string, key: crypto.KeyLike, signatureValue: string): boolean;
  verifySignature(
    material: string,
    key: crypto.KeyLike,
    signatureValue: string,
    callback?: ErrorFirstCallback<boolean>
  ): void;

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


function isErrorFirstCallback<T>(possibleCallback: unknown): possibleCallback is ErrorFirstCallback<T> {
  return typeof possibleCallback === "function"
}

/**
 * This function will add a callback version of a sync function.
 *
 * This follows the factory pattern.
 * Just call this function, passing the function that you'd like to add a callback version of.
 */
export function createOptionalCallbackFunction<T, A extends unknown[]>(
  syncVersion: (...args: A) => T
): {
  (...args: A): T;
  (...args: [...A, ErrorFirstCallback<T>]): void;
} {
  return ((...args: A | [...A, ErrorFirstCallback<T>]) => {
    const possibleCallback = args[args.length - 1];
    if (isErrorFirstCallback(possibleCallback)) {
      try {
        const result = syncVersion(...(args.slice(0, -1) as A));
        possibleCallback(null, result);
      } catch (err) {
        possibleCallback(err instanceof Error ? err : new Error("Unknown error"));
      }
    } else {
      return syncVersion(...(args as A));
    }
  }) as {
    (...args: A): T;
    (...args: [...A, ErrorFirstCallback<T>]): void;
  };
}

declare global {
  interface ArrayConstructor {
    isArray(arg: unknown): arg is Array<unknown> | ReadonlyArray<unknown>;
  }
}
