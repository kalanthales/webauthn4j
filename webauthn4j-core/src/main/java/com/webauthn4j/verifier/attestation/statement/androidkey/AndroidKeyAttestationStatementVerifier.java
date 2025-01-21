/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.verifier.attestation.statement.androidkey;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AndroidKeyAttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.SignatureUtil;
import com.webauthn4j.verifier.CoreRegistrationObject;
import com.webauthn4j.verifier.attestation.statement.AbstractStatementVerifier;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.exception.BadSignatureException;
import com.webauthn4j.verifier.exception.CertificateChainVerificationException;
import com.webauthn4j.verifier.exception.PublicKeyMismatchException;
import com.webauthn4j.verifier.exception.RootCertificateNotVerifiedException;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

public class AndroidKeyAttestationStatementVerifier extends AbstractStatementVerifier<AndroidKeyAttestationStatement> {

    // ~ Instance fields
    // ================================================================================================

    private final KeyDescriptionVerifier keyDescriptionVerifier = new KeyDescriptionVerifier();
    private boolean teeEnforcedOnly = true;

    // The Google root public key corresponding to the private key that must
    // have been used to self-sign the root of a real attestation certificate
    // chain from a compliant device.
    // (Note, the sample chain used here is not signed with the Google root CA.)
    public static final String GOOGLE_ROOT_CA_PUB_KEY =
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU"
                    + "FmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j"
                    + "lRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y"
                    + "//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X"
                    + "pXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI"
                    + "mQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB"
                    + "+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q"
                    + "uvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp"
                    + "Zrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7"
                    + "gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82"
                    + "ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+"
                    + "NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==";

    @Override
    public @NotNull AttestationType verify(@NotNull CoreRegistrationObject registrationObject) {
        AssertUtil.notNull(registrationObject, "registrationObject must not be null");

        if (!supports(registrationObject)) {
            throw new IllegalArgumentException(String.format("Specified format '%s' is not supported by %s.", registrationObject.getAttestationObject().getFormat(), this.getClass().getName()));
        }

        AndroidKeyAttestationStatement attestationStatement =
                (AndroidKeyAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        verifyAttestationStatementNotNull(attestationStatement);

        if (attestationStatement.getX5c().isEmpty()) {
            throw new BadAttestationStatementException("No attestation certificate is found in android key attestation statement.");
        }

        /// Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.

        /// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the public key in the first certificate in x5c with the algorithm specified in alg.
        verifySignature(registrationObject);

        /// Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
        PublicKey publicKeyInEndEntityCert = attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate().getPublicKey();
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = registrationObject.getAttestationObject().getAuthenticatorData();
        //noinspection ConstantConditions as null check is already done in caller
        PublicKey publicKeyInCredentialData = authenticatorData.getAttestedCredentialData().getCOSEKey().getPublicKey();
        if (!publicKeyInEndEntityCert.equals(publicKeyInCredentialData)) {
            throw new PublicKeyMismatchException("The public key in the first certificate in x5c doesn't matches the credentialPublicKey in the attestedCredentialData in authenticatorData.");
        }

        byte[] clientDataHash = registrationObject.getClientDataHash();
        keyDescriptionVerifier.verify(attestationStatement.getX5c().getEndEntityAttestationCertificate().getCertificate(), clientDataHash, teeEnforcedOnly);

        // Verify the root certificate should be signed with the Google attestation root key
        verifyGoogleRootCA(attestationStatement.getX5c().get(attestationStatement.getX5c().size()-1));

        // Verify current certificate's signature using the previous certificate's public key
        verifyCertificateChain(attestationStatement.getX5c());

        return AttestationType.BASIC;
    }

    void verifyAttestationStatementNotNull(AndroidKeyAttestationStatement attestationStatement) {
        if (attestationStatement == null) {
            throw new BadAttestationStatementException("attestation statement is not found.");
        }
    }

    private void verifySignature(@NotNull CoreRegistrationObject registrationObject) {
        AndroidKeyAttestationStatement attestationStatement = (AndroidKeyAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        byte[] signedData = getSignedData(registrationObject);
        byte[] signature = attestationStatement.getSig();
        PublicKey publicKey = getPublicKey(attestationStatement);

        try {
            String jcaName;
            jcaName = getJcaName(attestationStatement.getAlg());
            Signature verifier = SignatureUtil.createSignature(jcaName);
            verifier.initVerify(publicKey);
            verifier.update(signedData);
            if (verifier.verify(signature)) {
                return;
            }
            throw new BadSignatureException("`sig` in attestation statement is not valid signature over the concatenation of authenticatorData and clientDataHash.");
        } catch (SignatureException | InvalidKeyException e) {
            throw new BadSignatureException("`sig` in attestation statement is not valid signature over the concatenation of authenticatorData and clientDataHash.", e);
        }
    }

    private void verifyCertificateChain(@NotNull AttestationCertificatePath x5c){
        try {
            // Start from the last certificate (root) and move backward
            for (int i = x5c.size() - 1; i > 0; i--) {
                X509Certificate currentCert = x5c.get(i);
                X509Certificate previousCert = x5c.get(i-1);

                // Verify current certificate's signature using the previous certificate's public key
                previousCert.verify(currentCert.getPublicKey());
                //Certificate " + i + " correctly signs the previous certificate."
            }
            return;
        } catch (Exception e) {
            throw  new CertificateChainVerificationException("Certificate chain verification failed");
        }
    }
    private void verifyGoogleRootCA(X509Certificate lastCert){
        // If the attestation is trustworthy and the device ships with hardware-
        // backed key attestation, Android 7.0 (API level 24) or higher, and
        // Google Play services, the root certificate should be signed with the
        // Google attestation root key.
        byte[] googleRootCaPubKey = Base64.getDecoder().decode(GOOGLE_ROOT_CA_PUB_KEY);
        if (Arrays.equals(
                googleRootCaPubKey,
                lastCert.getPublicKey().getEncoded())) {
            //The root certificate is correct, so this attestation is trustworthy, as long as none of
            //the certificates in the chain have been revoked.
            return;
        } else {
            throw new RootCertificateNotVerifiedException("The root certificate is NOT correct. The attestation was probably generated by"
                    + " software, not in secure hardware. This means that there is no guarantee that the"
                    + " claims within the attestation are correct. If you're using a production-level"
                    + " system, you should disregard any claims made within this attestation certificate"
                    + " as there is no authority backing them up.");

        }
    }

    private @NotNull byte[] getSignedData(@NotNull CoreRegistrationObject registrationObject) {
        byte[] authenticatorData = registrationObject.getAuthenticatorDataBytes();
        byte[] clientDataHash = registrationObject.getClientDataHash();
        return ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();
    }

    private @NotNull PublicKey getPublicKey(@NotNull AndroidKeyAttestationStatement attestationStatement) {
        AttestationCertificatePath x5c = attestationStatement.getX5c();
        Certificate cert = x5c.getEndEntityAttestationCertificate().getCertificate();
        return cert.getPublicKey();
    }

    public boolean isTeeEnforcedOnly() {
        return teeEnforcedOnly;
    }

    public void setTeeEnforcedOnly(boolean teeEnforcedOnly) {
        this.teeEnforcedOnly = teeEnforcedOnly;
    }
}
