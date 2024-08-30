import { IDL, query, update, time } from "azle";
import jws from "jws";
import * as jose from "jose";

/**
 * Link to the DOC: https://internetcomputer.org/docs/current/developer-docs/identity/verifiable-credentials/issuer
 * Link to candid Interface: https://github.com/dfinity/internet-identity/blob/main/docs/vc-spec.md
 */
type CredentialSpec = {
  credential_type: string;
  arguments?: [string, ArgumentValue][];
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
    error_code: IDL.Int,
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

type PrepareCredentialRequest = {
  signed_id_alias: SignedIdAlias;
  credential_spec: CredentialSpec;
};

type SignedIdAlias = {
  credential_jws: string;
};

const AzleSignedIdAliasType = IDL.Record({
  credential_jws: IDL.Text,
});

const AzlePrepareCredentialRequestType = IDL.Record({
  signed_id_alias: AzleSignedIdAliasType,
  credential_spec: AzleCredentialSpecType,
});

type PreparedCredentialData = {
  prepared_context?: Uint8Array;
};

const AzlePreparedCredentialDataType = IDL.Record({
  prepared_context: IDL.Opt(IDL.Nat8),
});

type GetCredentialRequest = {
  signed_id_alias: SignedIdAlias;
  credential_spec: CredentialSpec;
  prepared_context?: Uint8Array;
};

const AzleGetCredentialRequestType = IDL.Record({
  signed_id_alias: AzleSignedIdAliasType,
  credential_spec: AzleCredentialSpecType,
  prepared_context: IDL.Opt(IDL.Int8),
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

const supportedOrigins = ["https://dacade.org", "http://be2us-64aaa-aaaaa-qaabq-cai.localhost:4943", "http://bkyz2-fmaaa-aaaaa-qaaaq-cai.localhost:4943"];
const II_CREDENTIAL_URL_PREFIX = "data:text/plain;charset=UTF-8,";
const II_ISSUER_URL = "https://identity.ic0.app/";
const VC_SIGNING_INPUT_DOMAIN = "iccs_verifiable_credential";
const DID_ICP_PREFIX = "did:icp:";

interface VerifiableCredentialService {
  derivation_origin(request: DerivationOriginRequest): { Ok: DerivationOriginData } | { Err: DerivationOriginError };
  vc_consent_message(request: Icrc21VcConsentMessageRequest): { Ok: Icrc21ConsentInfo } | { Err: Icrc21Error };
  prepare_credential(request: PrepareCredentialRequest): { Ok: PreparedCredentialData } | { Err: IssueCredentialError };
  get_credential(request: GetCredentialRequest): { Ok: IssuedCredentialData } | { Err: IssueCredentialError };
}

export default class {
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
    [AzlePrepareCredentialRequestType],
    IDL.Variant({
      Ok: AzlePreparedCredentialDataType,
      Err: AzleIssueCredentialErrorType,
    }),
  )
  async prepare_credential(request: PrepareCredentialRequest): Promise<{ Ok: PreparedCredentialData } | { Err: IssueCredentialError }> {
    // const credentialJws = request.signed_id_alias.credential_jws;
    // console.log({ credentialJws });
    //
    // const decodedJWS = jws.decode(credentialJws);
    // console.log({ decodedJWS });
    // if (!decodedJWS) return { Err: { UnknownSubject: "JWS not found" } };
    // const jwk = decodedJWS.header.jwk;
    // if (!jwk) return { Err: { SignatureNotFound: "Signature not found" } };
    // // @ts-ignore
    // if (jwk.alg?.toLowerCase() !== "iccs") return { Err: { UnknownSubject: "Unsupported Algorithm" } };
    // if (jwk.kty !== "oct") return { Err: { UnknownSubject: "Expected JWK of type oct" } };
    // const jwk_params = jwk?.k;
    // if (!jwk_params) return { Err: { UnknownSubject: "Expected K params in the JWK" } };
    //
    // const payload = JSON.parse(decodedJWS.payload);
    // if (payload.iss !== II_ISSUER_URL) return { Err: { UnknownSubject: "II issuer not supported" } };
    // if (!payload.jti.startWith(II_CREDENTIAL_URL_PREFIX)) return { Err: { UnknownSubject: "Wrong credential prefix" } };
    //
    // const subjectPrincipal = ic.caller();
    // console.log({ subjectPrincipal });
    // console.log({ decodedJWS });

    // const result = {
    //   [request.credential_spec.credential_type]: request.credential_spec.arguments,
    // };
    //
    // const serializedArgs = {};
    //
    // result[request.credential_spec.credential_type]?.[0]?.forEach((item) => {
    //   const [key, valueObj] = item;
    //   if (typeof valueObj !== "string") {
    //     serializedArgs[key] = valueObj.String || valueObj.Int;
    //   } else {
    //     serializedArgs[key] = valueObj;
    //   }
    // });

    // const credentialData = { [request.credential_spec.credential_type]: serializedArgs };

    return {
      Ok: {
        prepared_context: Buffer.from("hello", "utf-8"),
      },
    };
  }

  @query([AzleGetCredentialRequestType], IDL.Record({ Ok: AzleIssuedCredentialDataType, Err: AzleIssueCredentialErrorType }))
  get_credential(request: GetCredentialRequest): { Ok: IssuedCredentialData } | { Err: IssueCredentialError } {
    console.log({ getCredentialRequest: request });
    return { Ok: { vc_jws: "string" } };
  }
}
