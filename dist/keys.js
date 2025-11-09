import { exportJWK, generateKeyPair, importJWK, importPKCS8, importSPKI, SignJWT, jwtVerify, } from "jose";
let statePromise = null;
function env(name) {
    const v = process.env[name];
    return v && v.trim().length > 0 ? v : undefined;
}
function pickAlg() {
    const alg = env("AUTH_ALG") || "EdDSA";
    return alg;
}
function randomKid() {
    return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
export async function initKeys() {
    if (statePromise)
        return statePromise;
    statePromise = (async () => {
        const alg = pickAlg();
        const envPriv = env("AUTH_PRIVATE_KEY_PEM");
        const envPub = env("AUTH_PUBLIC_KEY_PEM");
        const envJwkPriv = env("AUTH_PRIVATE_JWK");
        const envJwkPub = env("AUTH_PUBLIC_JWK");
        let privateKey;
        let publicKey;
        let publicJwk;
        if (envJwkPriv) {
            const jwk = JSON.parse(envJwkPriv);
            privateKey = (await importJWK(jwk, jwk.alg));
            if (envJwkPub) {
                publicKey = (await importJWK(JSON.parse(envJwkPub), jwk.alg));
            }
            else {
                publicJwk = { ...jwk };
                delete publicJwk.d;
                publicKey = (await importJWK(publicJwk, jwk.alg));
            }
            publicJwk ||= await exportJWK(publicKey);
        }
        else if (envPriv && envPub) {
            if (alg === "EdDSA") {
                privateKey = await importPKCS8(envPriv, alg);
                publicKey = await importSPKI(envPub, alg);
            }
            else if (alg.startsWith("RS")) {
                privateKey = await importPKCS8(envPriv, alg);
                publicKey = await importSPKI(envPub, alg);
            }
            else if (alg.startsWith("ES")) {
                privateKey = await importPKCS8(envPriv, alg);
                publicKey = await importSPKI(envPub, alg);
            }
            else {
                throw new Error(`Unsupported PEM import for alg ${alg}`);
            }
            publicJwk = await exportJWK(publicKey);
        }
        else {
            // Generate a fresh keypair for dev.
            const { publicKey: pub, privateKey: priv } = await generateKeyPair(alg === "HS256" ? "HS256" : alg);
            privateKey = priv;
            publicKey = pub;
            publicJwk = await exportJWK(publicKey);
        }
        const kid = env("AUTH_KID") || randomKid();
        publicJwk.kid = kid;
        publicJwk.alg = alg;
        publicJwk.use = "sig";
        return { alg, kid, privateKey, publicKey, publicJwk };
    })();
    return statePromise;
}
export async function jwks() {
    const st = await initKeys();
    return { keys: [st.publicJwk] };
}
export async function signAccessToken(payload, opts) {
    const st = await initKeys();
    const issuer = env("AUTH_ISSUER") || "http://localhost:8088";
    const exp = opts?.expiresIn ??
        (process.env.AUTH_TOKEN_TTL_SECONDS
            ? Number(process.env.AUTH_TOKEN_TTL_SECONDS)
            : 3600);
    const now = Math.floor(Date.now() / 1000);
    const jwt = await new SignJWT(payload)
        .setProtectedHeader({ alg: st.alg, kid: st.kid })
        .setIssuedAt(now)
        .setIssuer(issuer)
        .setExpirationTime(typeof exp === "number" ? now + exp : exp)
        .sign(st.privateKey);
    return jwt;
}
export async function verifyToken(token) {
    const st = await initKeys();
    const issuer = env("AUTH_ISSUER") || "http://localhost:8088";
    const res = await jwtVerify(token, st.publicKey, { issuer });
    return res;
}
//# sourceMappingURL=keys.js.map