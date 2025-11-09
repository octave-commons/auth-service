import { JWK, KeyLike } from "jose";
export type SupportedAlg = "EdDSA" | "RS256" | "RS512" | "ES256" | "ES384" | "ES512" | "HS256";
type KeyState = {
    alg: SupportedAlg;
    kid: string;
    privateKey: KeyLike;
    publicKey: KeyLike;
    publicJwk: JWK;
};
export declare function initKeys(): Promise<KeyState>;
export declare function jwks(): Promise<{
    keys: JWK[];
}>;
export declare function signAccessToken(payload: Record<string, any>, opts?: {
    expiresIn?: string | number;
}): Promise<string>;
export declare function verifyToken(token: string): Promise<import("jose").JWTVerifyResult<import("jose").JWTPayload>>;
export {};
//# sourceMappingURL=keys.d.ts.map