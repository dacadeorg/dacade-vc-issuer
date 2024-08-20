import { IDL, query, update } from "azle";

/**
 * Link to the DOC: https://internetcomputer.org/docs/current/developer-docs/identity/verifiable-credentials/issuer
 * Link to candid Interface: https://github.com/dfinity/internet-identity/blob/main/docs/vc-spec.md
 */
type CredentialSpec = {
  credential_type: string;
  arguments?: [string, ArgumentValue][];
};

const AzleCredentialSpecType = IDL.Record({
  credential_type: IDL.Text,
  arguments: IDL.Vec(IDL.Record({})),
});

type ArgumentValue = { Int: number } | { String: string };

const AzleArgumentValueType = IDL.Variant({
  Int: IDL.Int,
  String: IDL.Text,
});

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

type Icrc21Error =
  | { GenericError: { description: string; error_code: number } }
  | { UnsupportedCanisterCall: Icrc21ErrorInfo }
  | { ConsentMessageUnavailable: Icrc21ErrorInfo };

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

const AzlePrepareCredentialRequestType = {
  signed_id_alias: AzleSignedIdAliasType,
  credential_spec: AzleCredentialSpecType,
};

type PreparedCredentialData = {
  prepared_context?: Uint8Array;
};

const AzlePreparedCredentialDataType = IDL.Record({
  prepared_context: IDL.Opt(IDL.Int8),
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

type DerivationOriginError =
  | { Internal: string }
  | { UnsupportedOrigin: string };

const AzleDerivationOriginErrorType = IDL.Variant({
  Internal: IDL.Text,
  UnsupportedOrigin: IDL.Text,
});

const supportedCredentials = [
  "ICP 101 completion",
  "ICP 201 completion",
  "ICP DeAi Completion",
];

const supportedOrigins = ["dacade.org"];

interface VerifiableCredentialService {
  derivation_origin(
    request: DerivationOriginRequest
  ): Promise<{ Ok: DerivationOriginData } | { Err: DerivationOriginError }>;

  vc_consent_message(
    request: Icrc21VcConsentMessageRequest
  ): Promise<{ Ok: Icrc21ConsentInfo } | { Err: Icrc21Error }>;

  prepare_credential(
    request: PrepareCredentialRequest
  ): Promise<{ Ok: PreparedCredentialData } | { Err: IssueCredentialError }>;

  get_credential(
    request: GetCredentialRequest
  ): Promise<{ Ok: IssuedCredentialData } | { Err: IssueCredentialError }>;
}

export default class Canister implements VerifiableCredentialService {
  @query(
    [AzleDerivationOriginRequestType],
    IDL.Variant({
      Ok: AzleDerivationOriginDataType,
      Err: AzleDerivationOriginErrorType,
    })
  )
  async derivation_origin(
    request: DerivationOriginRequest
  ): Promise<{ Ok: DerivationOriginData } | { Err: DerivationOriginError }> {
    const originRequest = request.frontend_hostname;
    if (!supportedOrigins.includes(originRequest)) {
      return {
        Err: {
          UnsupportedOrigin: `${originRequest} is not supported`,
        },
      };
    }

    return { Ok: { origin: originRequest } };
  }

  @query(
    [AzleIcrc21VcConsentMessageRequestType],
    IDL.Variant({
      Ok: AzleIcrc21ConsentInfoType,
      Err: AzleIcrc21ErrorType,
    })
  )
  async vc_consent_message(
    request: Icrc21VcConsentMessageRequest
  ): Promise<{ Ok: Icrc21ConsentInfo } | { Err: Icrc21Error }> {
    if (
      !supportedCredentials.includes(request.credential_spec.credential_type)
    ) {
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

  @query([])
  async prepare_credential() {
    return { Ok: { prepared_context: [] } };
  }

  @query([])
  async get_credential() {
    return { Ok: { vc_jws: "string" } };
  }
}
