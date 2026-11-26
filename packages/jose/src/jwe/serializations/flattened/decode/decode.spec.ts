import { Buffer } from "node:buffer";

import { JSON } from "@avarin/primitives/json";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidJsonWebEncryptionError } from "../../../../errors/invalid-jsonwebencryption.error.ts";
import type { OctetSequenceJsonWebKeyParameters } from "../../../../jwa/jwk/oct/octet-sequence.jsonwebkey.parameters.ts";
import { JsonWebKey } from "../../../../jwk/jsonwebkey.ts";
import type { JsonWebEncryptionHeaderParameters } from "../../../header/jsonwebencryption.header.parameters.ts";
import { JsonWebEncryptionHeader } from "../../../header/jsonwebencryption.header.ts";
import type { FlattenedJsonWebEncryptionParameters } from "../flattened.jsonwebencryption.parameters.ts";
import type { FlattenedJsonWebEncryptionToken } from "../flattened.jsonwebencryption.token.ts";
import { decode } from "./decode.ts";

const fetchMock = vi.fn<typeof globalThis.fetch>();

const invalidTokens: any[] = [undefined, null, true, 1, 1.2, 1n, Symbol("a"), Buffer, Buffer.alloc(1), () => 1, []];

const invalidTokenFormats: any[] = [
  {},
  { protected: undefined },
  { protected: null },
  { protected: true },
  { protected: 1 },
  { protected: 1.2 },
  { protected: 1n },
  { protected: Symbol("a") },
  { protected: Buffer },
  { protected: Buffer.alloc(1) },
  { protected: () => 1 },
  { protected: {} },
  { protected: [] },
  { protected: "" },
  { protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", unprotected: undefined },
  { protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", unprotected: null },
  { protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", unprotected: true },
  { protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", unprotected: 1 },
  { protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", unprotected: 1.2 },
  { protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", unprotected: 1n },
  { protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", unprotected: "a" },
  { protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", unprotected: Symbol("a") },
  { protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", unprotected: Buffer },
  { protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", unprotected: Buffer.alloc(1) },
  { protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", unprotected: () => 1 },
  { protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", unprotected: [] },
  { header: undefined, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { header: null, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { header: true, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { header: 1, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { header: 1.2, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { header: 1n, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { header: "a", protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { header: Symbol("a"), protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { header: Buffer, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { header: Buffer.alloc(1), protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { header: () => 1, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { header: [], protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { encrypted_key: undefined, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { encrypted_key: null, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { encrypted_key: true, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { encrypted_key: 1, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { encrypted_key: 1.2, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { encrypted_key: 1n, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { encrypted_key: Symbol("a"), protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { encrypted_key: Buffer, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { encrypted_key: Buffer.alloc(1), protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { encrypted_key: () => 1, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { encrypted_key: {}, protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { encrypted_key: [], protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  { encrypted_key: "", protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" },
  {
    aad: undefined,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: null,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: true,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: 1,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: 1.2,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: 1n,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: Symbol("a"),
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: Buffer,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: Buffer.alloc(1),
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: () => 1,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: {},
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: [],
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: undefined,
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: null,
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: true,
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: 1,
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: 1.2,
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: 1n,
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: Symbol("a"),
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: Buffer,
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: Buffer.alloc(1),
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: () => 1,
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: {},
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: [],
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: undefined,
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: null,
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: true,
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: 1,
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: 1.2,
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: 1n,
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: Symbol("a"),
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: Buffer,
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: Buffer.alloc(1),
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: () => 1,
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: {},
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: [],
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: undefined,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: null,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: true,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: 1,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: 1.2,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: 1n,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: Symbol("a"),
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: Buffer,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: Buffer.alloc(1),
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: () => 1,
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: {},
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: [],
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
  { protected: "ew" },
  { protected: "e30" },
  {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  },
];

const repeatedJoseHeaderParameters: Partial<JsonWebEncryptionHeaderParameters>[][] = [
  [{ alg: "A128KW" }, { alg: "A128KW" }, { enc: "A128CBC-HS256" }],
  [{ alg: "A128KW" }, { enc: "A128CBC-HS256" }, { alg: "A128KW" }],
  [{ enc: "A128CBC-HS256" }, { alg: "A128KW" }, { alg: "A128KW" }],
  [{ alg: "A128KW" }, { alg: "A128KW" }, { alg: "A128KW" }],
];

describe("decode()", () => {
  const missingEncryptedKeyToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    header: { alg: "A128KW", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "U0m_YmjN04DJvceFICbCVQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };

  // #region Uncompressed Attached Token without Additional Authenticated Data
  const uncompressedProtectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  };

  const uncompressedUnprotectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "wOere2l7R7PoakOvvvxFCg",
    unprotected: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "wOere2l7R7PoakOvvvxFCg",
  };

  const uncompressedProtectedAndUnprotectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedProtectedAndRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
  };

  const uncompressedUnprotectedAndRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "wOere2l7R7PoakOvvvxFCg",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const uncompressedFullAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Uncompressed Detached Token without Additional Authenticated Data
  const uncompressedProtectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "pf7CC-iGb8R2ZstoWHErWw",
  };

  const uncompressedUnprotectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "wOere2l7R7PoakOvvvxFCg",
    unprotected: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "wOere2l7R7PoakOvvvxFCg",
  };

  const uncompressedProtectedAndUnprotectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedProtectedAndRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
  };

  const uncompressedUnprotectedAndRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "wOere2l7R7PoakOvvvxFCg",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const uncompressedFullDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "Mz-VPPyU4RlcuYv1IwIvzw",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Compressed Attached Token without Additional Authenticated Data
  const compressedProtectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "8nmSbluZF1Ws1sABt49r6Q",
  };

  const compressedUnprotectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
    unprotected: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
  };

  const compressedRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
  };

  const compressedProtectedAndUnprotectedAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
  };

  const compressedProtectedAndRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
  };

  const compressedUnprotectedAndRecipientAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const compressedFullAttachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Compressed Detached Token without Additional Authenticated Data
  const compressedProtectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "8nmSbluZF1Ws1sABt49r6Q",
  };

  const compressedUnprotectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
    unprotected: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
  };

  const compressedRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
  };

  const compressedProtectedAndUnprotectedDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
  };

  const compressedProtectedAndRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
  };

  const compressedUnprotectedAndRecipientDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "6mQsBNyxIUzsP37fC54ZjQ",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const compressedFullDetachedTokenNoAad: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "FVFsNAUL3jgdAmZnSVxAFQ",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Uncompressed Attached Token with Additional Authenticated Data
  const uncompressedProtectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "2WcnJIVXlq2EYEbHWKr-7g",
  };

  const uncompressedUnprotectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "W77Q108vf3uFnX_LmZPIlA",
    unprotected: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "W77Q108vf3uFnX_LmZPIlA",
  };

  const uncompressedProtectedAndUnprotectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "ULYMNP5lrIthBrdvAIzyqg",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedProtectedAndRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "ULYMNP5lrIthBrdvAIzyqg",
  };

  const uncompressedUnprotectedAndRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "W77Q108vf3uFnX_LmZPIlA",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const uncompressedFullAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "ULYMNP5lrIthBrdvAIzyqg",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Uncompressed Detached Token with Additional Authenticated Data
  const uncompressedProtectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9." +
      "YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "2WcnJIVXlq2EYEbHWKr-7g",
  };

  const uncompressedUnprotectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "W77Q108vf3uFnX_LmZPIlA",
    unprotected: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", enc: "A128CBC-HS256", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "W77Q108vf3uFnX_LmZPIlA",
  };

  const uncompressedProtectedAndUnprotectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "ULYMNP5lrIthBrdvAIzyqg",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
  };

  const uncompressedProtectedAndRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "ULYMNP5lrIthBrdvAIzyqg",
  };

  const uncompressedUnprotectedAndRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "W77Q108vf3uFnX_LmZPIlA",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const uncompressedFullDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "ULYMNP5lrIthBrdvAIzyqg",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Compressed Attached Token with Additional Authenticated Data
  const compressedProtectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9." +
      "YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "SRoHlcdRqnsVScLWNZIwtA",
  };

  const compressedUnprotectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
    unprotected: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
  };

  const compressedRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
  };

  const compressedProtectedAndUnprotectedAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
  };

  const compressedProtectedAndRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
  };

  const compressedUnprotectedAndRecipientAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const compressedFullAttachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    ciphertext: "7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion
  // #region Compressed Detached Token with Additional Authenticated Data
  const compressedProtectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9." +
      "YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected:
      "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiemlwIjoiREVGIiwiamt1IjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20va2V5cy5qd2tzIiwia2lkIjoiNyJ9",
    tag: "SRoHlcdRqnsVScLWNZIwtA",
  };

  const compressedUnprotectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
    unprotected: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
  };

  const compressedRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: {
      alg: "A128KW",
      enc: "A128CBC-HS256",
      jku: "https://server.example.com/keys.jwks",
      kid: "7",
      zip: "DEF",
    },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
  };

  const compressedProtectedAndUnprotectedDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
    unprotected: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
  };

  const compressedProtectedAndRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
  };

  const compressedUnprotectedAndRecipientDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: ".YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", jku: "https://server.example.com/keys.jwks", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    tag: "0Z9lyKxM6Rz-6zCUcfNOmQ",
    unprotected: { enc: "A128CBC-HS256" },
  };

  const compressedFullDetachedToken: FlattenedJsonWebEncryptionToken = {
    aad: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE",
    encrypted_key: "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    header: { alg: "A128KW", kid: "7", zip: "DEF" },
    iv: "AxY8DCtDaGlsbGljb3RoZQ",
    protected: "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    tag: "1IIFfjlJQ4EkqwKhBdlY5w",
    unprotected: { jku: "https://server.example.com/keys.jwks" },
  };
  // #endregion

  const encHeader: Partial<JsonWebEncryptionHeaderParameters> = { enc: "A128CBC-HS256" };
  const jkuHeader: Partial<JsonWebEncryptionHeaderParameters> = { jku: "https://server.example.com/keys.jwks" };
  const algKidHeader: Partial<JsonWebEncryptionHeaderParameters> = { alg: "A128KW", kid: "7" };

  const algZipKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: "A128KW",
    kid: "7",
    zip: "DEF",
  };

  const algJkuKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: "A128KW",
    jku: "https://server.example.com/keys.jwks",
    kid: "7",
  };

  const algEncJkuKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: "A128KW",
    enc: "A128CBC-HS256",
    jku: "https://server.example.com/keys.jwks",
    kid: "7",
  };

  const algZipJkuKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: "A128KW",
    jku: "https://server.example.com/keys.jwks",
    kid: "7",
    zip: "DEF",
  };

  const algEncZipJkuKidHeader: Partial<JsonWebEncryptionHeaderParameters> = {
    alg: "A128KW",
    enc: "A128CBC-HS256",
    jku: "https://server.example.com/keys.jwks",
    kid: "7",
    zip: "DEF",
  };

  const encryptedKey = Buffer.from("6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ", "base64url");
  const initializationVector = Buffer.from("AxY8DCtDaGlsbGljb3RoZQ", "base64url");
  const ciphertext = Buffer.from("KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY", "base64url");
  const compressedCiphertext = Buffer.from("7_74Yt9JQPazdQVzwCiocFWXSAtgczzDQVUY9WXJ7KA", "base64url");
  const additionalAuthenticatedData = Buffer.from("YWRkaXRpb25hbF9hdXRoZW50aWNhdGVkX2RhdGE", "base64url");

  const jsonWebKey = new JsonWebKey<OctetSequenceJsonWebKeyParameters>({
    k: "GawgguFyGrWKav7AX4VKUg",
    kid: "7",
    kty: "oct",
  });

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);

    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ keys: [jsonWebKey.parameters] }),
    } as Response);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetAllMocks();
  });

  it.each(invalidTokens)(
    "should throw when the provided Flattened JSON Web Encryption Token is invalid.",
    async (token) => {
      const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
      await expect(decode(token)).rejects.toThrow(error);
    },
  );

  it.each(invalidTokenFormats)(
    "should throw when the provided Flattened JSON Web Encryption Token has an invalid format.",
    async (token) => {
      const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");
      await expect(decode(token)).rejects.toThrow(error);
    },
  );

  it.each(repeatedJoseHeaderParameters)(
    "should throw when there are repeated JSON Web Encryption Header Parameters.",
    async (protectedHeader, unprotectedHeader, recipientUnprotectedHeader) => {
      const error = new InvalidJsonWebEncryptionError("The provided JSON Web Encryption is invalid.");

      await expect(
        decode({
          ...uncompressedProtectedAttachedTokenNoAad,
          header: recipientUnprotectedHeader,
          protected: Buffer.from(JSON.stringify(protectedHeader), "utf8").toString("base64url"),
          unprotected: unprotectedHeader,
        }),
      ).rejects.toThrow(error);
    },
  );

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("pf7CC-iGb8R2ZstoWHErWw", "base64url"),
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: algEncJkuKidHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("wOere2l7R7PoakOvvvxFCg", "base64url"),
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("wOere2l7R7PoakOvvvxFCg", "base64url"),
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: algEncJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("Mz-VPPyU4RlcuYv1IwIvzw", "base64url"),
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("Mz-VPPyU4RlcuYv1IwIvzw", "base64url"),
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("wOere2l7R7PoakOvvvxFCg", "base64url"),
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedFullAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("Mz-VPPyU4RlcuYv1IwIvzw", "base64url"),
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("pf7CC-iGb8R2ZstoWHErWw", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: algEncJkuKidHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("wOere2l7R7PoakOvvvxFCg", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("wOere2l7R7PoakOvvvxFCg", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: algEncJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("Mz-VPPyU4RlcuYv1IwIvzw", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("Mz-VPPyU4RlcuYv1IwIvzw", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("wOere2l7R7PoakOvvvxFCg", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedFullDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("Mz-VPPyU4RlcuYv1IwIvzw", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Protected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("8nmSbluZF1Ws1sABt49r6Q", "base64url"),
      ciphertext: compressedCiphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: algEncZipJkuKidHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("6mQsBNyxIUzsP37fC54ZjQ", "base64url"),
      ciphertext: compressedCiphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncZipJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("6mQsBNyxIUzsP37fC54ZjQ", "base64url"),
      ciphertext: compressedCiphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: algEncZipJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Unprotected Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("FVFsNAUL3jgdAmZnSVxAFQ", "base64url"),
      ciphertext: compressedCiphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("FVFsNAUL3jgdAmZnSVxAFQ", "base64url"),
      ciphertext: compressedCiphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientAttachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("6mQsBNyxIUzsP37fC54ZjQ", "base64url"),
      ciphertext: compressedCiphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed protected, Unprotected and Recipient Attached Token with no Additional Authenticated Data.", async () => {
    await expect(decode(compressedFullAttachedTokenNoAad)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData: null,
        authenticationTag: Buffer.from("FVFsNAUL3jgdAmZnSVxAFQ", "base64url"),
        ciphertext: compressedCiphertext,
        encryptedKey,
        header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
        initializationVector,
        protectedHeader: encHeader,
        recipientUnprotectedHeader: algZipKidHeader,
        unprotectedHeader: jkuHeader,
      },
    );
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Protected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("8nmSbluZF1Ws1sABt49r6Q", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: algEncZipJkuKidHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("6mQsBNyxIUzsP37fC54ZjQ", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncZipJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("6mQsBNyxIUzsP37fC54ZjQ", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: algEncZipJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Unprotected Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("FVFsNAUL3jgdAmZnSVxAFQ", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("FVFsNAUL3jgdAmZnSVxAFQ", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientDetachedTokenNoAad),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("6mQsBNyxIUzsP37fC54ZjQ", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed protected, Unprotected and Recipient Detached Token with no Additional Authenticated Data.", async () => {
    await expect(decode(compressedFullDetachedTokenNoAad)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData: null,
        authenticationTag: Buffer.from("FVFsNAUL3jgdAmZnSVxAFQ", "base64url"),
        ciphertext: null,
        encryptedKey,
        header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
        initializationVector,
        protectedHeader: encHeader,
        recipientUnprotectedHeader: algZipKidHeader,
        unprotectedHeader: jkuHeader,
      },
    );
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("2WcnJIVXlq2EYEbHWKr-7g", "base64url"),
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: algEncJkuKidHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("W77Q108vf3uFnX_LmZPIlA", "base64url"),
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedRecipientAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("W77Q108vf3uFnX_LmZPIlA", "base64url"),
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: algEncJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("ULYMNP5lrIthBrdvAIzyqg", "base64url"),
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("ULYMNP5lrIthBrdvAIzyqg", "base64url"),
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("W77Q108vf3uFnX_LmZPIlA", "base64url"),
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(decode(uncompressedFullAttachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("ULYMNP5lrIthBrdvAIzyqg", "base64url"),
      ciphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("2WcnJIVXlq2EYEbHWKr-7g", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: algEncJkuKidHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("W77Q108vf3uFnX_LmZPIlA", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedRecipientDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("W77Q108vf3uFnX_LmZPIlA", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: algEncJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndUnprotectedDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("ULYMNP5lrIthBrdvAIzyqg", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedProtectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("ULYMNP5lrIthBrdvAIzyqg", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(uncompressedUnprotectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("W77Q108vf3uFnX_LmZPIlA", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: algJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from an Uncompressed Protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(decode(uncompressedFullDetachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("ULYMNP5lrIthBrdvAIzyqg", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Protected Attached Token with Additional Authenticated Data.", async () => {
    await expect(decode(compressedProtectedAttachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData,
        authenticationTag: Buffer.from("SRoHlcdRqnsVScLWNZIwtA", "base64url"),
        ciphertext: compressedCiphertext,
        encryptedKey,
        header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
        initializationVector,
        protectedHeader: algEncZipJkuKidHeader,
        recipientUnprotectedHeader: null,
        unprotectedHeader: null,
      },
    );
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedUnprotectedAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("0Z9lyKxM6Rz-6zCUcfNOmQ", "base64url"),
      ciphertext: compressedCiphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncZipJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(decode(compressedRecipientAttachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData,
        authenticationTag: Buffer.from("0Z9lyKxM6Rz-6zCUcfNOmQ", "base64url"),
        ciphertext: compressedCiphertext,
        encryptedKey,
        header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
        initializationVector,
        protectedHeader: null,
        recipientUnprotectedHeader: algEncZipJkuKidHeader,
        unprotectedHeader: null,
      },
    );
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Unprotected Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("1IIFfjlJQ4EkqwKhBdlY5w", "base64url"),
      ciphertext: compressedCiphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("1IIFfjlJQ4EkqwKhBdlY5w", "base64url"),
      ciphertext: compressedCiphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientAttachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("0Z9lyKxM6Rz-6zCUcfNOmQ", "base64url"),
      ciphertext: compressedCiphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed protected, Unprotected and Recipient Attached Token with Additional Authenticated Data.", async () => {
    await expect(decode(compressedFullAttachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("1IIFfjlJQ4EkqwKhBdlY5w", "base64url"),
      ciphertext: compressedCiphertext,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Protected Detached Token with Additional Authenticated Data.", async () => {
    await expect(decode(compressedProtectedDetachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData,
        authenticationTag: Buffer.from("SRoHlcdRqnsVScLWNZIwtA", "base64url"),
        ciphertext: null,
        encryptedKey,
        header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
        initializationVector,
        protectedHeader: algEncZipJkuKidHeader,
        recipientUnprotectedHeader: null,
        unprotectedHeader: null,
      },
    );
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedUnprotectedDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("0Z9lyKxM6Rz-6zCUcfNOmQ", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algEncZipJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(decode(compressedRecipientDetachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>(
      {
        additionalAuthenticatedData,
        authenticationTag: Buffer.from("0Z9lyKxM6Rz-6zCUcfNOmQ", "base64url"),
        ciphertext: null,
        encryptedKey,
        header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
        initializationVector,
        protectedHeader: null,
        recipientUnprotectedHeader: algEncZipJkuKidHeader,
        unprotectedHeader: null,
      },
    );
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Unprotected Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndUnprotectedDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("1IIFfjlJQ4EkqwKhBdlY5w", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: null,
      unprotectedHeader: algZipJkuKidHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Protected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedProtectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("1IIFfjlJQ4EkqwKhBdlY5w", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: null,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(
      decode(compressedUnprotectedAndRecipientDetachedToken),
    ).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("0Z9lyKxM6Rz-6zCUcfNOmQ", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: null,
      recipientUnprotectedHeader: algZipJkuKidHeader,
      unprotectedHeader: encHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Compressed protected, Unprotected and Recipient Detached Token with Additional Authenticated Data.", async () => {
    await expect(decode(compressedFullDetachedToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData,
      authenticationTag: Buffer.from("1IIFfjlJQ4EkqwKhBdlY5w", "base64url"),
      ciphertext: null,
      encryptedKey,
      header: new JsonWebEncryptionHeader(algEncZipJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algZipKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });

  it("should return the Flattened JSON Web Encryption Parameters from a Token without an Encrypted Key.", async () => {
    await expect(decode(missingEncryptedKeyToken)).resolves.toStrictEqual<FlattenedJsonWebEncryptionParameters>({
      additionalAuthenticatedData: null,
      authenticationTag: Buffer.from("U0m_YmjN04DJvceFICbCVQ", "base64url"),
      ciphertext,
      encryptedKey: null,
      header: new JsonWebEncryptionHeader(algEncJkuKidHeader as JsonWebEncryptionHeaderParameters),
      initializationVector,
      protectedHeader: encHeader,
      recipientUnprotectedHeader: algKidHeader,
      unprotectedHeader: jkuHeader,
    });
  });
});
