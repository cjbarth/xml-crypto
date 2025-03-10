// Type definitions for @node-saml/xml-crypto
// Project: https://github.com/node-saml/xml-crypto#readme
// Original definitions by: Eric Heikes <https://github.com/eheikes>
//                          Max Chehab <https://github.com/maxchehab>

/// <reference types="node" />

import { SelectedValue } from 'xpath';

export class HashAlgorithm {
    getAlgorithmName(): string;
    getHash(xml: string): string;
}

export interface Reference {
    xpath: string;
    transforms?: ReadonlyArray<string> | undefined;
    digestAlgorithm?: string | undefined;
    uri?: string | undefined;
    digestValue?: string | undefined;
    inclusiveNamespacesPrefixList?: string | undefined;
    isEmptyUri?: boolean | undefined;
}

export class SignatureAlgorithm {
    getAlgorithmName(): string;
    getSignature(signedInfo: Node, signingKey: Buffer): string;
}

export class TransformationAlgorithm {
    getAlgorithmName(): string;
    process(node: Node): string;
}

export class SignedXml {
    static CanonicalizationAlgorithms: {[uri: string]: new () => TransformationAlgorithm };
    static HashAlgorithms: {[uri: string]: new () => HashAlgorithm};
    static SignatureAlgorithms: {[uri: string]: new () => SignatureAlgorithm};
    canonicalizationAlgorithm: string;
    inclusiveNamespacesPrefixList: string;
    keyInfoProvider: KeyInfo;
    references: Reference[];
    signatureAlgorithm: string;
    signingKey: Buffer | string;
    validationErrors: string[];
    constructor(idMode?: string | null, options?: {
        canonicalizationAlgorithm?: string | undefined
        inclusiveNamespacesPrefixList?: string | undefined
        idAttribute?: string | undefined
        implicitTransforms?: ReadonlyArray<string> | undefined
        signatureAlgorithm?: string | undefined
    })
    addReference(
        xpath: string,
        transforms?: ReadonlyArray<string>,
        digestAlgorithm?: string,
        uri?: string,
        digestValue?: string,
        inclusiveNamespacesPrefixList?: string,
        isEmptyUri?: boolean
    ): void;
    checkSignature(xml: string): boolean;
    computeSignature(
        xml: string,
        opts?: {
            prefix?: string | undefined,
            attrs?: {[key: string]: any} | undefined,
            location?: {
                reference: string,
                action: 'append' | 'prepend' | 'before' |  'after'
            } | undefined,
            existingPrefixes?: {[prefix: string]: string} | undefined
        }
    ): void;
    getOriginalXmlWithIds(): string;
    getSignatureXml(): string;
    getSignedXml(): string;
    loadSignature(signatureNode: string | Node): void;
}

export interface KeyInfo {
    getKey(keyInfo?: Node[] | null): Buffer;
    getKeyInfo(key?: string, prefix?: string): string;
    attrs?: {[key: string]: any} | undefined;
}

export class FileKeyInfo implements KeyInfo {
    file: string;
    constructor(file?: string);
    getKey(keyInfo?: Node[] | null): Buffer;
    getKeyInfo(key?: string, prefix?: string): string;
}

export class StringKeyInfo implements KeyInfo {
    key: string;
    constructor(key?: string);
    getKey(keyInfo?: Node[] | null): Buffer;
    getKeyInfo(key?: string, prefix?: string): string;
}

export function xpath(node: Node, xpath: string): SelectedValue[];
