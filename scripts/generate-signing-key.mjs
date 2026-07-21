// Optional key-rotation helper. Run with Node.js 22+.
// After rotation, update the key ID/public key in worker/worker.js and every SDK.
const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
console.log("ELITEAUTH_SIGNING_PRIVATE_JWK=");
console.log(JSON.stringify(privateJwk));
console.log("\nPinned public key (JWK x):");
console.log(publicJwk.x);
