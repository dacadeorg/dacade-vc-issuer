import { IDL, Principal, query, update, caller, id } from "azle";
import jws from "jws";
import * as jose from "jose";
import { sha256 } from "js-sha256";

/**
 * Link to the DOC: https://internetcomputer.org/docs/current/developer-docs/identity/verifiable-credentials/issuer
 * Link to candid Interface and specification: https://github.com/dfinity/internet-identity/blob/main/docs/vc-spec.md
 */
type CredentialSpec = {
  credential_type: string;
  arguments: [] | [Array<[string, ArgumentValue]>];
};

const AzleArgumentValueType = IDL.Variant({
  Int: IDL.Int32,
  String: IDL.Text,
});

const AzleCredentialSpecType = IDL.Record({
  credential_type: IDL.Text,
  arguments: IDL.Opt(IDL.Vec(IDL.Tuple(IDL.Text, AzleArgumentValueType))),
});

type ArgumentValue = { Int: number } | { String: string };

type Icrc21ConsentInfo = {
  consent_message: string;
  language: string;
};

const AzleIcrc21ConsentInfoType = IDL.Record({
  consent_message: IDL.Text,
  language: IDL.Text,
});

type Icrc21ConsentPreferences = {
  language: string;
};

const AzleIcrc21ConsentPreferencesType = IDL.Record({
  language: IDL.Text,
});

type Icrc21Error = { GenericError: { description: string; error_code: number } } | { UnsupportedCanisterCall: Icrc21ErrorInfo } | { ConsentMessageUnavailable: Icrc21ErrorInfo };

type Icrc21ErrorInfo = {
  description: string;
};

const AzleIcrc21ErrorInfoType = IDL.Record({
  description: IDL.Text,
});

const AzleIcrc21ErrorType = IDL.Variant({
  GenericError: IDL.Record({
    description: IDL.Text,
    error_code: IDL.Nat,
  }),
  UnsupportedCanisterCall: AzleIcrc21ErrorInfoType,
  ConsentMessageUnavailable: AzleIcrc21ErrorInfoType,
});

type Icrc21VcConsentMessageRequest = {
  preferences: Icrc21ConsentPreferences;
  credential_spec: CredentialSpec;
};

const AzleIcrc21VcConsentMessageRequestType = IDL.Record({
  preferences: AzleIcrc21ConsentPreferencesType,
  credential_spec: AzleCredentialSpecType,
});

type PrepareCredentialRequestType = {
  signed_id_alias: SignedIdAlias;
  credential_spec: CredentialSpec;
};

type SignedIdAlias = {
  credential_jws: string;
};

const AzleSignedIdAliasType = IDL.Record({
  credential_jws: IDL.Text,
});

const PrepareCredentialRequest = IDL.Record({
  signed_id_alias: AzleSignedIdAliasType,
  credential_spec: AzleCredentialSpecType,
});

type PreparedCredentialDataType = {
  prepared_context: [] | [Uint8Array | number[]];
};

const PreparedCredentialData = IDL.Record({
  prepared_context: IDL.Opt(IDL.Vec(IDL.Nat8)),
});

type GetCredentialRequest = {
  signed_id_alias: SignedIdAlias;
  credential_spec: CredentialSpec;
  prepared_context?: [] | [Uint8Array | number[]];
};

const AzleGetCredentialRequestType = IDL.Record({
  signed_id_alias: AzleSignedIdAliasType,
  credential_spec: AzleCredentialSpecType,
  prepared_context: IDL.Opt(IDL.Vec(IDL.Nat8)),
});

type IssuedCredentialData = {
  vc_jws: string;
};

const AzleIssuedCredentialDataType = IDL.Record({
  vc_jws: IDL.Text,
});

type IssueCredentialError =
  | { UnknownSubject: string }
  | { UnauthorizedSubject: string }
  | { InvalidIdAlias: string }
  | { UnsupportedCredentialSpec: string }
  | { SignatureNotFound: string }
  | { Internal: string };

const AzleIssueCredentialErrorType = IDL.Variant({
  UnknownSubject: IDL.Text,
  UnauthorizedSubject: IDL.Text,
  InvalidIdAlias: IDL.Text,
  UnsupportedCredentialSpec: IDL.Text,
  SignatureNotFound: IDL.Text,
  Internal: IDL.Text,
});

type DerivationOriginRequest = {
  frontend_hostname: string;
};

const AzleDerivationOriginRequestType = IDL.Record({
  frontend_hostname: IDL.Text,
});

type DerivationOriginData = {
  origin: string;
};

const AzleDerivationOriginDataType = IDL.Record({
  origin: IDL.Text,
});

type DerivationOriginError = { Internal: string } | { UnsupportedOrigin: string };

const AzleDerivationOriginErrorType = IDL.Variant({
  Internal: IDL.Text,
  UnsupportedOrigin: IDL.Text,
});

const supportedCredentials = ["ICP 101 completion", "ICP 201 completion", "ICP DeAi Completion"];
const supportedOrigins = ["https://dacade.org", "http://be2us-64aaa-aaaaa-qaabq-cai.localhost:4943", "http://ajuq4-ruaaa-aaaaa-qaaga-cai.localhost:4943"];
const CREDENTIAL_URL_PREFIX = "data:text/plain;charset=UTF-8,";
const ISSUER_URL = "https://identity.ic0.app/";
const VC_SIGNING_INPUT_DOMAIN = "iccs_verifiable_credential";
const DID_ICP_PREFIX = "did:icp:";
const MINUTE_NS = 60n * 1_000_000_000n;
const VC_EXPIRATION_PERIOD_NS = 15n * MINUTE_NS;
const CANISTER_SIG_SEED = hashBytes("DacadeIssuer");
const CANISTER_SIG_PK = {
  canisterId: id(),
  seed: CANISTER_SIG_SEED,
};

interface VerifiableCredentialService {
  derivation_origin(request: DerivationOriginRequest): { Ok: DerivationOriginData } | { Err: DerivationOriginError };
  vc_consent_message(request: Icrc21VcConsentMessageRequest): { Ok: Icrc21ConsentInfo } | { Err: Icrc21Error };
  prepare_credential(request: PrepareCredentialRequestType): { Ok: PreparedCredentialDataType } | { Err: IssueCredentialError };
  get_credential(request: GetCredentialRequest): Promise<{ Ok: IssuedCredentialData } | { Err: IssueCredentialError }>;
}

function hashBytes(value: string): Uint8Array {
  return new Uint8Array(sha256.array(value));
}

function expTimestampS(): number {
  return Number((BigInt(Date.now()) * 1_000_000n + VC_EXPIRATION_PERIOD_NS) / 1_000_000_000n);
}

export default class Canister implements VerifiableCredentialService {
  @update(
    [AzleDerivationOriginRequestType],
    IDL.Variant({
      Ok: AzleDerivationOriginDataType,
      Err: AzleDerivationOriginErrorType,
    }),
  )
  derivation_origin(request: DerivationOriginRequest): { Ok: DerivationOriginData } | { Err: DerivationOriginError } {
    const originRequest = request.frontend_hostname;
    if (!supportedOrigins.includes(originRequest)) {
      return {
        Err: {
          UnsupportedOrigin: `${originRequest} is not supported`,
        },
      };
    }
    console.log({ originRequest });
    return { Ok: { origin: originRequest } };
  }

  @update(
    [AzleIcrc21VcConsentMessageRequestType],
    IDL.Variant({
      Ok: AzleIcrc21ConsentInfoType,
      Err: AzleIcrc21ErrorType,
    }),
  )
  vc_consent_message(request: Icrc21VcConsentMessageRequest): { Ok: Icrc21ConsentInfo } | { Err: Icrc21Error } {
    console.log({ consentMessageRequest: request });
    if (!supportedCredentials.includes(request.credential_spec.credential_type)) {
      return {
        Err: {
          UnsupportedCanisterCall: {
            description: `Dacade cannot provide ${request.credential_spec.credential_type} type of credentials`,
          },
        },
      };
    }
    return {
      Ok: {
        consent_message: `You are requesting ${request.credential_spec.credential_type} credentials`,
        language: request.preferences.language,
      },
    };
  }

  @update(
    [PrepareCredentialRequest],
    IDL.Variant({
      Ok: PreparedCredentialData,
      Err: AzleIssueCredentialErrorType,
    }),
  )
  prepare_credential(request: PrepareCredentialRequestType): { Ok: PreparedCredentialDataType } | { Err: IssueCredentialError } {
    // 1. Verify the signed_id_alias
    const decodedJWS = jws.decode(request.signed_id_alias.credential_jws);
    if (!decodedJWS) {
      return { Err: { InvalidIdAlias: "Invalid JWS format" } };
    }

    // 2. Verify the JWS header
    const jwk = decodedJWS.header.jwk;
    if (!jwk || jwk.alg?.toLowerCase() !== "iccs" || jwk.kty !== "oct") {
      return { Err: { InvalidIdAlias: "Invalid JWS header" } };
    }

    // 3. Verify the JWS payload
    const payload = JSON.parse(decodedJWS.payload);
    console.log({ payload });
    if (payload.iss !== ISSUER_URL || !payload.jti.startsWith(CREDENTIAL_URL_PREFIX)) {
      return { Err: { InvalidIdAlias: "Invalid JWS payload" } };
    }

    // 4. Verify the credential spec
    if (!supportedCredentials.includes(request.credential_spec.credential_type)) {
      return { Err: { UnsupportedCredentialSpec: `Unsupported credential type: ${request.credential_spec.credential_type}` } };
    }

    // 5. Verify the subject
    const subjectPrincipal = caller();
    if (!this.isAuthorizedSubject(subjectPrincipal, request.credential_spec)) {
      return { Err: { UnauthorizedSubject: "Subject is not authorized for this credential" } };
    }

    // 6. Prepare the credential data
    const credentialData = this.prepareCredentialData(request.credential_spec, subjectPrincipal);

    // 7. Encode the prepared context
    const preparedContext = new TextEncoder().encode(JSON.stringify(credentialData));
    return {
      Ok: {
        prepared_context: [preparedContext],
      },
    };
  }
  @query([AzleGetCredentialRequestType], IDL.Record({ Ok: AzleIssuedCredentialDataType, Err: AzleIssueCredentialErrorType }))
  async get_credential(request: GetCredentialRequest): Promise<{ Ok: IssuedCredentialData } | { Err: IssueCredentialError }> {
    console.log({ getCredentialRequest: request });

    // 1. Verify the request
    if (!request.prepared_context) {
      return { Err: { Internal: "Missing prepared context" } };
    }

    if (request.prepared_context[0] === undefined) {
      return { Err: { Internal: "Missing prepared context" } };
    }

    // 2. Decode and verify the prepared context
    let credentialData;
    try {
      credentialData = JSON.parse(new TextDecoder().decode(request.prepared_context[0] as Uint8Array));
    } catch (error) {
      return { Err: { Internal: "Invalid prepared context" } };
    }

    console.log({ credentialData });
    // 3. Verify that the credential data matches the request
    if (!credentialData.type.includes(request.credential_spec.credential_type)) {
      return { Err: { UnsupportedCredentialSpec: "Credential type mismatch" } };
    }

    // 5. Sign the VC
    const signedVC = await this.signVC(credentialData, request.credential_spec.credential_type);
    console.log({ signedVC });
    return { Ok: { vc_jws: signedVC } };
  }

  private isAuthorizedSubject(principal: Principal, credentialSpec: CredentialSpec): boolean {
    // Authorize all subjects for now
    return true;
  }

  private prepareCredentialData(credentialSpec: CredentialSpec, subject: Principal) {
    const serializedArgs = this.parseVcDataPayload(credentialSpec.credential_type, credentialSpec.arguments);
    return {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential", credentialSpec.credential_type],
      issuer: ISSUER_URL,
      issuanceDate: new Date().toISOString(),
      expirationDate: new Date(Date.now() + Number(VC_EXPIRATION_PERIOD_NS) / 1000000).toISOString(),
      credentialSubject: {
        id: `did:icp:${subject.toText()}`,
        ...serializedArgs,
      },
      id: this.credentialIdForPrincipal(subject),
    };
  }

  private parseVcDataPayload(credential_type: string, credential_arguments: [string, ArgumentValue][][]) {
    const serializedArgs: Record<string, string | number> = {};
    credential_arguments[0].forEach(([key, valueObj]) => {
      (serializedArgs as Record<string, string | number>)[key] = "String" in valueObj ? valueObj.String : valueObj.Int;
    });

    return {
      [credential_type]: serializedArgs,
    };
  }

  private credentialIdForPrincipal(subjectPrincipal: Principal): string {
    const issuer = `issuer:${ISSUER_URL}`;
    const timestamp = `timestamp_ns:${BigInt(Date.now()) * 1_000_000n}`;
    const subject = `subject:${subjectPrincipal.toText()}`;
    return `${CREDENTIAL_URL_PREFIX}${issuer},${timestamp},${subject}`;
  }

  private async signVC(vc: ReturnType<typeof this.prepareCredentialData>, credential_type: string): Promise<string> {
    const header = { alg: "HS256" };

    console.log({ data: vc.credentialSubject?.[credential_type], btoa });

    const jwt = new jose.CompactSign(new TextEncoder().encode(JSON.stringify(vc))).setProtectedHeader({ alg: "HS256" }).sign(new TextEncoder().encode("dacade.org"));

    console.log({ jwt: await jwt });
    return await jwt;
  }
}
