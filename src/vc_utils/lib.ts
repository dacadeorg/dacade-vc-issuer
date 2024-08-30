import { Principal } from "azle";
import { base64url } from "jose";
import jws, { Signature } from "jws";
import * as buffer from "node:buffer";

const II_CREDENTIAL_URL_PREFIX = "data:text/plain;charset=UTF-8,";
const II_ISSUER_URL = "https://identity.ic0.app/";
const VC_SIGNING_INPUT_DOMAIN = "iccs_verifiable_credential";
const DID_ICP_PREFIX = "did:icp:";

// ref: https://github.com/dfinity/internet-identity/blob/main/src/vc_util/src/lib.rs#L629

export const IC_ROOT_PK_DER_PREFIX: Uint8Array = new Uint8Array([
  0x30, 0x81, 0x82, 0x30, 0x1d, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x7c, 0x05, 0x03, 0x01, 0x02, 0x01, 0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc,
  0x7c, 0x05, 0x03, 0x02, 0x01, 0x03, 0x61, 0x00,
]);

export const IC_ROOT_PK_DER: Uint8Array = new Uint8Array([
  0x30, 0x81, 0x82, 0x30, 0x1d, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x7c, 0x05, 0x03, 0x01, 0x02, 0x01, 0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc,
  0x7c, 0x05, 0x03, 0x02, 0x01, 0x03, 0x61, 0x00, 0x81, 0x4c, 0x0e, 0x6e, 0xc7, 0x1f, 0xab, 0x58, 0x3b, 0x08, 0xbd, 0x81, 0x37, 0x3c, 0x25, 0x5c, 0x3c, 0x37, 0x1b, 0x2e, 0x84,
  0x86, 0x3c, 0x98, 0xa4, 0xf1, 0xe0, 0x8b, 0x74, 0x23, 0x5d, 0x14, 0xfb, 0x5d, 0x9c, 0x0c, 0xd5, 0x46, 0xd9, 0x68, 0x5f, 0x91, 0x3a, 0x0c, 0x0b, 0x2c, 0xc5, 0x34, 0x15, 0x83,
  0xbf, 0x4b, 0x43, 0x92, 0xe4, 0x67, 0xdb, 0x96, 0xd6, 0x5b, 0x9b, 0xb4, 0xcb, 0x71, 0x71, 0x12, 0xf8, 0x47, 0x2e, 0x0d, 0x5a, 0x4d, 0x14, 0x50, 0x5f, 0xfd, 0x74, 0x84, 0xb0,
  0x12, 0x91, 0x09, 0x1c, 0x5f, 0x87, 0xb9, 0x88, 0x83, 0x46, 0x3f, 0x98, 0x09, 0x1a, 0x0b, 0xaa, 0xae,
]);

export const IC_ROOT_PK_LENGTH: number = 96;

export const CANISTER_SIG_PK_DER_PREFIX_LENGTH: number = 19;

export const CANISTER_SIG_PK_DER_OID: Uint8Array = new Uint8Array([0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xb8, 0x43, 0x01, 0x02]);

function extractRawCanisterSigPkFromDer(pkDer: Uint8Array) {
  const oidPart = pkDer.subarray(2, CANISTER_SIG_PK_DER_OID.length + 2);
  if (!oidPart.every((value, index) => value === CANISTER_SIG_PK_DER_OID[index])) {
    return new Error("invalid OID of canister sig pk");
  }

  const bitstringOffset = CANISTER_SIG_PK_DER_PREFIX_LENGTH;
  const canisterIdLen = pkDer.length > bitstringOffset ? pkDer[bitstringOffset] : undefined;

  if (canisterIdLen === undefined) {
    return new Error("canister sig pk shorter than DER prefix");
  }

  if (pkDer.length < bitstringOffset + 1 + canisterIdLen) {
    return new Error("canister sig pk too short");
  }

  return pkDer.subarray(bitstringOffset);
}

function signingInputWithPrefix(signingInput: Uint8Array): Uint8Array {
  const VC_SIGNING_INPUT_DOMAIN_ = Buffer.from(VC_SIGNING_INPUT_DOMAIN);

  const result = new Uint8Array(1 + VC_SIGNING_INPUT_DOMAIN_.length + signingInput.length);

  result[0] = VC_SIGNING_INPUT_DOMAIN_.length;

  result.set(VC_SIGNING_INPUT_DOMAIN_, 1);
  result.set(signingInput, 1 + VC_SIGNING_INPUT_DOMAIN_.length);
  return result;
}

export function get_canister_sig_pk_raw(jws_signature: Signature) {
  const jwk = jws_signature.header.jwk;
  if (!jwk) return new Error("Missing JWK signature");
  // @ts-ignore
  if (jwk.alg !== "IcCs") return new Error("Unsupported Algorithm");
  if (jwk.kty !== "oct") return new Error("Expected JWK of type oct");
  const jwk_params = jwk?.k;
  if (!jwk_params) return new Error("Expected K params in the JWK");
  const pk_der = base64url.decode(Buffer.from(jwk_params));
  const pk_raw = extractRawCanisterSigPkFromDer(pk_der);
  if (pk_raw instanceof Error) {
    return new Error(pk_raw.message);
  }
  return pk_raw;
}

export function verify_credential_jws_with_canister_id(credential_jws: string, expected_vc_subject: Principal, signingCanisterId: Principal) {
  let decodedJWS: Signature | null;
  try {
    decodedJWS = jws.decode(credential_jws);
    if (decodedJWS === null) {
      return { Err: { UnknownSubject: "JWS not found" } };
    }
    let canister_sig_pk_raw = get_canister_sig_pk_raw(decodedJWS);
  } catch (e) {
    return { Err: { UnknownSubject: "Invalid JWT" } };
  }
}

export function get_verified_id_alias_from_jws(credential_jws: string, expected_vc_subject: Principal, signingCanisterId: Principal) {}
