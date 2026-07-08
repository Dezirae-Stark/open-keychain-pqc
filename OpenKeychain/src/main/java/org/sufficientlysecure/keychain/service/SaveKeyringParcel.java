/*
 * Copyright (C) 2017 Schürmann & Breitmoser GbR
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.sufficientlysecure.keychain.service;


import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import android.os.Parcelable;
import androidx.annotation.Nullable;

import com.google.auto.value.AutoValue;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.sufficientlysecure.keychain.keyimport.HkpKeyserverAddress;
import org.sufficientlysecure.keychain.pgp.WrappedUserAttribute;
import org.sufficientlysecure.keychain.util.Passphrase;

/**
 * This class is a a transferable representation for a collection of changes
 * to be done on a keyring.
 * <p/>
 * This class should include all types of operations supported in the backend.
 * <p/>
 * All changes are done in a differential manner. Besides the two key
 * identification attributes, all attributes may be null, which indicates no
 * change to the keyring. This is also the reason why boxed values are used
 * instead of primitives in the subclasses.
 * <p/>
 * Application of operations in the backend should be fail-fast, which means an
 * error in any included operation (for example revocation of a non-existent
 * subkey) will cause the operation as a whole to fail.
 */
@AutoValue
public abstract class SaveKeyringParcel implements Parcelable {

    // the master key id to be edited. if this is null, a new one will be created
    @Nullable
    public abstract Long getMasterKeyId();
    // the key fingerprint, for safety. MUST be null for a new key.
    @Nullable
    @SuppressWarnings("mutable")
    public abstract byte[] getFingerprint();

    public abstract List<String> getAddUserIds();
    public abstract List<WrappedUserAttribute> getAddUserAttribute();
    public abstract List<SubkeyAdd> getAddSubKeys();

    public abstract List<SubkeyChange> getChangeSubKeys();
    @Nullable
    public abstract String getChangePrimaryUserId();

    public abstract List<String> getRevokeUserIds();
    public abstract List<Long> getRevokeSubKeys();

    // if these are non-null, PINs will be changed on the token
    @Nullable
    public abstract Passphrase getSecurityTokenPin();
    @Nullable
    public abstract Passphrase getSecurityTokenAdminPin();

    public abstract boolean isShouldUpload();
    public abstract boolean isShouldUploadAtomic();
    @Nullable
    public abstract HkpKeyserverAddress getUploadKeyserver();

    @Nullable
    public abstract ChangeUnlockParcel getNewUnlock();

    public static Builder buildNewKeyringParcel() {
        return new AutoValue_SaveKeyringParcel.Builder()
                .setShouldUpload(false)
                .setShouldUploadAtomic(false);
    }

    public static Builder buildChangeKeyringParcel(long masterKeyId, byte[] fingerprint) {
        return buildNewKeyringParcel()
                .setMasterKeyId(masterKeyId)
                .setFingerprint(fingerprint);
    }

    abstract Builder toBuilder();

    public static Builder buildUpon(SaveKeyringParcel saveKeyringParcel) {
        SaveKeyringParcel.Builder builder = saveKeyringParcel.toBuilder();
        builder.addUserIds.addAll(saveKeyringParcel.getAddUserIds());
        builder.revokeUserIds.addAll(saveKeyringParcel.getRevokeUserIds());
        builder.addUserAttribute.addAll(saveKeyringParcel.getAddUserAttribute());
        builder.addSubKeys.addAll(saveKeyringParcel.getAddSubKeys());
        builder.changeSubKeys.addAll(saveKeyringParcel.getChangeSubKeys());
        builder.revokeSubKeys.addAll(saveKeyringParcel.getRevokeSubKeys());
        return builder;
    }

    @AutoValue.Builder
    public static abstract class Builder {
        private ArrayList<String> addUserIds = new ArrayList<>();
        private ArrayList<String> revokeUserIds = new ArrayList<>();
        private ArrayList<WrappedUserAttribute> addUserAttribute = new ArrayList<>();
        private ArrayList<SubkeyAdd> addSubKeys = new ArrayList<>();
        private ArrayList<SubkeyChange> changeSubKeys = new ArrayList<>();
        private ArrayList<Long> revokeSubKeys = new ArrayList<>();


        public abstract Builder setChangePrimaryUserId(String changePrimaryUserId);
        public abstract Builder setSecurityTokenPin(Passphrase securityTokenPin);
        public abstract Builder setSecurityTokenAdminPin(Passphrase securityTokenAdminPin);
        public abstract Builder setNewUnlock(ChangeUnlockParcel newUnlock);

        public abstract Long getMasterKeyId();
        public abstract byte[] getFingerprint();
        public abstract String getChangePrimaryUserId();


        public ArrayList<SubkeyAdd> getMutableAddSubKeys() {
            return addSubKeys;
        }
        public ArrayList<String> getMutableAddUserIds() {
            return addUserIds;
        }
        public ArrayList<Long> getMutableRevokeSubKeys() {
            return revokeSubKeys;
        }
        public ArrayList<String> getMutableRevokeUserIds() {
            return revokeUserIds;
        }

        abstract Builder setMasterKeyId(Long masterKeyId);
        abstract Builder setFingerprint(byte[] fingerprint);
        abstract Builder setAddUserIds(List<String> addUserIds);
        abstract Builder setAddUserAttribute(List<WrappedUserAttribute> addUserAttribute);
        abstract Builder setAddSubKeys(List<SubkeyAdd> addSubKeys);
        abstract Builder setChangeSubKeys(List<SubkeyChange> changeSubKeys);
        abstract Builder setRevokeUserIds(List<String> revokeUserIds);
        abstract Builder setRevokeSubKeys(List<Long> revokeSubKeys);
        abstract Builder setShouldUpload(boolean upload);
        abstract Builder setShouldUploadAtomic(boolean uploadAtomic);
        abstract Builder setUploadKeyserver(HkpKeyserverAddress keyserver);

        public void setUpdateOptions(boolean upload, boolean uploadAtomic, HkpKeyserverAddress keyserver) {
            setShouldUpload(upload);
            setShouldUploadAtomic(uploadAtomic);
            setUploadKeyserver(keyserver);
        }

        public void addSubkeyAdd(SubkeyAdd subkeyAdd) {
            addSubKeys.add(subkeyAdd);
        }

        public void addUserId(String userId) {
            addUserIds.add(userId);
        }

        public void addRevokeSubkey(long masterKeyId) {
            revokeSubKeys.add(masterKeyId);
        }

        public void removeRevokeSubkey(long keyId) {
            revokeSubKeys.remove(keyId);
        }

        public void addRevokeUserId(String userId) {
            revokeUserIds.add(userId);
        }

        public void removeRevokeUserId(String userId) {
            revokeUserIds.remove(userId);
        }

        public void addOrReplaceSubkeyChange(SubkeyChange newChange) {
            SubkeyChange foundSubkeyChange = getSubkeyChange(newChange.getSubKeyId());

            if (foundSubkeyChange != null) {
                changeSubKeys.remove(foundSubkeyChange);
            }
            changeSubKeys.add(newChange);
        }

        public void removeSubkeyChange(SubkeyChange change) {
            changeSubKeys.remove(change);
        }

        public SubkeyChange getSubkeyChange(long keyId) {
            if (changeSubKeys == null) {
                return null;
            }

            for (SubkeyChange subkeyChange : changeSubKeys) {
                if (subkeyChange.getSubKeyId() == keyId) {
                    return subkeyChange;
                }
            }
            return null;
        }

        public void addUserAttribute(WrappedUserAttribute ua) {
            addUserAttribute.add(ua);
        }

        abstract SaveKeyringParcel autoBuild();

        public SaveKeyringParcel build() {
            setAddUserAttribute(Collections.unmodifiableList(addUserAttribute));
            setRevokeSubKeys(Collections.unmodifiableList(revokeSubKeys));
            setRevokeUserIds(Collections.unmodifiableList(revokeUserIds));
            setAddSubKeys(Collections.unmodifiableList(addSubKeys));
            setAddUserIds(Collections.unmodifiableList(addUserIds));
            setChangeSubKeys(Collections.unmodifiableList(changeSubKeys));

            return autoBuild();
        }

        public boolean hasModificationsForSubkey(long keyId) {
            return revokeSubKeys.contains(keyId) || getSubkeyChange(keyId) != null;
        }

        public void removeModificationsForSubkey(long keyId) {
            revokeSubKeys.remove(keyId);
            SubkeyChange subkeyChange = getSubkeyChange(keyId);
            if (subkeyChange != null) {
                changeSubKeys.remove(subkeyChange);
            }
        }
    }

    // performance gain for using Parcelable here would probably be negligible,
    // use Serializable instead.
    @AutoValue
    public abstract static class SubkeyAdd implements Serializable {
        public abstract Algorithm getAlgorithm();
        @Nullable
        public abstract Integer getKeySize();
        @Nullable
        public abstract Curve getCurve();
        public abstract int getFlags();
        @Nullable
        public abstract Long getExpiry();

        public static SubkeyAdd createSubkeyAdd(Algorithm algorithm, Integer keySize, Curve curve, int flags,
                Long expiry) {
            return new AutoValue_SaveKeyringParcel_SubkeyAdd(algorithm, keySize, curve, flags, expiry);
        }

        public boolean canCertify() {
            return (getFlags() & KeyFlags.CERTIFY_OTHER) > 0;
        }

        public boolean canSign() {
            return (getFlags() & KeyFlags.SIGN_DATA) > 0;
        }

        public boolean canEncrypt() {
            return ((getFlags() & KeyFlags.ENCRYPT_COMMS) > 0) || ((getFlags() & KeyFlags.ENCRYPT_STORAGE) > 0);
        }

        public boolean canAuthenticate() {
            return (getFlags() & KeyFlags.AUTHENTICATION) > 0;
        }
    }

    @AutoValue
    public abstract static class SubkeyChange implements Serializable {
        public abstract long getSubKeyId();
        @Nullable
        public abstract Integer getFlags();
        // this is a long unix timestamp, in seconds (NOT MILLISECONDS!)
        @Nullable
        public abstract Long getExpiry();
        // if this flag is true, the key will be recertified even if all above
        // values are no-ops
        public abstract boolean getRecertify();
        // if this flag is true, the subkey should be changed to a stripped key
        public abstract boolean getDummyStrip();
        // if this flag is true, the subkey should be moved to a security token
        public abstract boolean getMoveKeyToSecurityToken();
        // if this is non-null, the subkey will be changed to a divert-to-card
        // (security token) key for the given serial number
        @Nullable
        @SuppressWarnings("mutable")
        public abstract byte[] getSecurityTokenSerialNo();

        public static SubkeyChange createRecertifyChange(long keyId, boolean recertify) {
            return new AutoValue_SaveKeyringParcel_SubkeyChange(keyId, null, null, recertify, false, false, null);
        }

        public static SubkeyChange createFlagsOrExpiryChange(long keyId, Integer flags, Long expiry) {
            return new AutoValue_SaveKeyringParcel_SubkeyChange(keyId, flags, expiry, false, false, false, null);
        }

        public static SubkeyChange createStripChange(long keyId) {
            return new AutoValue_SaveKeyringParcel_SubkeyChange(keyId, null, null, false, true, false, null);
        }

        public static SubkeyChange createMoveToSecurityTokenChange(long keyId) {
            return new AutoValue_SaveKeyringParcel_SubkeyChange(keyId, null, null, false, false, true, null);
        }

        public static SubkeyChange createSecurityTokenSerialNo(long keyId, byte[] securityTokenSerialNo) {
            return new AutoValue_SaveKeyringParcel_SubkeyChange(keyId, null, null, false, false, false, securityTokenSerialNo);
        }
    }

    // All supported algorithms
    public enum Algorithm {
        RSA, DSA, ELGAMAL, ECDSA, ECDH, EDDSA,
        // Composite ML-KEM-768+X25519 (draft-ietf-openpgp-pqc-17, algorithm ID 35).
        // Encryption-only; no key size/curve selection needed (see PgpKeyOperation).
        ML_KEM_768_X25519,
        // Composite ML-KEM-1024+X448 (draft-ietf-openpgp-pqc-17, algorithm ID 36).
        // Encryption-only; no key size/curve selection needed (see PgpKeyOperation). Unlike
        // ML_KEM_768_X25519, this algorithm requires v6 keys (no v4 allowance) -- see
        // CompositeMlKem1024X448's Javadoc.
        ML_KEM_1024_X448,
        // Composite ML-DSA-65+Ed25519 (draft-ietf-openpgp-pqc-17, algorithm ID 30).
        // Signing/certifying-only; no key size/curve selection needed (see PgpKeyOperation).
        // Unlike ML_KEM_768_X25519, this algorithm requires v6 keys and signatures (no v4
        // allowance) -- see CompositeMlDsa65Ed25519's Javadoc.
        ML_DSA_65_ED25519,
        // Composite ML-DSA-87+Ed448 (draft-ietf-openpgp-pqc-17, algorithm ID 31).
        // Signing/certifying-only; no key size/curve selection needed (see PgpKeyOperation).
        // Same v6-only requirement (no v4 allowance) as ML_DSA_65_ED25519 -- see
        // CompositeMlDsa87Ed448's Javadoc.
        ML_DSA_87_ED448,
        // Standalone (non-composite -- no classical/ECC component at all) SLH-DSA-SHAKE-128s
        // (draft-ietf-openpgp-pqc-17, algorithm ID 32). Signing/certifying-only; no key size/
        // curve selection needed (see PgpKeyOperation). Same v6-only requirement (no v4
        // allowance) as the composite algorithms above -- see SlhDsaShake128s's Javadoc.
        SLH_DSA_SHAKE_128S,
        // Standalone (non-composite, closed-ecosystem) ML-KEM-768 -- OpenKeychain private-use
        // algorithm ID 100. Unlike every algorithm above, this is NOT defined by
        // draft-ietf-openpgp-pqc-17 or any other spec -- see
        // docs/superpowers/specs/2026-07-07-pqc-migration-design.md (Standalone Mode
        // section) and StandaloneMlKem768's Javadoc. Encryption-only; v6-only (no v4
        // allowance). See SaveKeyringParcel#isNonStandardClosedEcosystemPqc(Algorithm).
        STANDALONE_ML_KEM_768,
        // Standalone (non-composite, closed-ecosystem) ML-KEM-1024 -- OpenKeychain private-use
        // algorithm ID 101. Same rationale as STANDALONE_ML_KEM_768 above.
        STANDALONE_ML_KEM_1024,
        // Standalone (non-composite, closed-ecosystem) ML-DSA-65 -- OpenKeychain private-use
        // algorithm ID 102. NOT defined by draft-ietf-openpgp-pqc-17 or any other spec -- see
        // docs/superpowers/specs/2026-07-07-pqc-migration-design.md (Standalone Mode section)
        // and StandaloneMlDsa65's Javadoc. Signing/certifying-only; v6-only (no v4 allowance).
        // See SaveKeyringParcel#isNonStandardClosedEcosystemPqc(Algorithm).
        STANDALONE_ML_DSA_65,
        // Standalone (non-composite, closed-ecosystem) ML-DSA-87 -- OpenKeychain private-use
        // algorithm ID 103. Same rationale as STANDALONE_ML_DSA_65 above.
        STANDALONE_ML_DSA_87
    }

    /**
     * Returns true if {@code algorithm} is a private-use, closed-ecosystem PQC construction
     * that is <b>not</b> defined by draft-ietf-openpgp-pqc-17 or any other spec, and will
     * <b>not</b> interoperate with GnuPG, Sequoia, RNP, or any other OpenPGP implementation --
     * including any future implementation of draft-ietf-openpgp-pqc-17 itself, since the
     * draft never defines these code points. See
     * docs/superpowers/specs/2026-07-07-pqc-migration-design.md (Standalone/Closed-Ecosystem
     * Mode section).
     * <p>
     * No UI currently surfaces this flag to the user -- this method exists so that a future
     * UI phase has a single, authoritative place to query it from (key-generation warning
     * dialogs, key-listing badges, etc.) rather than needing its own algorithm-ID-based
     * judgment call scattered across call sites.
     */
    public static boolean isNonStandardClosedEcosystemPqc(Algorithm algorithm) {
        switch (algorithm) {
            case STANDALONE_ML_KEM_768:
            case STANDALONE_ML_KEM_1024:
            case STANDALONE_ML_DSA_65:
            case STANDALONE_ML_DSA_87:
                return true;
            default:
                return false;
        }
    }

    // All curves defined in the standard
    // http://www.bouncycastle.org/wiki/pages/viewpage.action?pageId=362269
    public enum Curve {
        NIST_P256, NIST_P384, NIST_P521, CV25519

        // these are supported by gpg, but they are not in rfc6637 and not supported by BouncyCastle yet
        // (adding support would be trivial though -> JcaPGPKeyConverter.java:190)
        // BRAINPOOL_P256, BRAINPOOL_P384, BRAINPOOL_P512
    }
}
