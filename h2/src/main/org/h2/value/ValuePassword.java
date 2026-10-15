/*
 * Copyright 2004-2026 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (https://h2database.com/html/license.html).
 */
package org.h2.value;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.h2.engine.CastDataProvider;
import org.h2.message.DbException;
import org.h2.security.SHA256;
import org.h2.util.MathUtils;
import org.h2.util.StringUtils;
import org.h2.util.Utils;

/**
 * A password credential. The value is an encoded credential, never plaintext.
 * Format: $h2p$1$pbkdf2-sha256$600000$ followed by 16 salt bytes and 32
 * derived bytes, each encoded as lowercase hexadecimal and separated by $.
 */
public final class ValuePassword extends ValueStringBase {

    private static final String PREFIX = "$h2p$1$pbkdf2-sha256$600000$";
    private static final int ITERATIONS = 600_000;
    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;

    private final byte[] salt;
    private final byte[] hash;

    private ValuePassword(String encoded, byte[] salt, byte[] hash) {
        super(encoded);
        this.salt = salt;
        this.hash = hash;
    }

    @Override
    public int getValueType() {
        return PASSWORD;
    }

    @Override
    public StringBuilder getSQL(StringBuilder builder, int sqlFlags) {
        return StringUtils.quoteStringSQL(builder, value);
    }

    /**
     * Create a new credential from plaintext, including an empty password.
     * Each call uses a new secure random salt. The text is encoded as UTF-8.
     *
     * @param plaintext plaintext password
     * @return a new credential
     */
    public static ValuePassword get(String plaintext) {
        if (plaintext == null) {
            throw DbException.getInvalidValueException("password", "null");
        }
        byte[] salt = MathUtils.secureRandomBytes(SALT_LENGTH);
        byte[] hash = derive(plaintext, salt);
        return new ValuePassword(encode(salt, hash), salt, hash);
    }

    /**
     * Restore an encoded credential without deriving a new hash or salt.
     * Intended for the storage adapter; never use this for SQL plaintext input.
     *
     * @param encoded encoded credential
     * @return the restored credential
     */
    public static ValuePassword fromEncoded(String encoded) {
        if (encoded == null || !encoded.startsWith(PREFIX)) {
            throw invalidCredential();
        }
        int separator = encoded.indexOf('$', PREFIX.length());
        if (separator != PREFIX.length() + SALT_LENGTH * 2
                || encoded.length() != separator + 1 + HASH_LENGTH * 2) {
            throw invalidCredential();
        }
        byte[] salt = decode(encoded, PREFIX.length(), SALT_LENGTH);
        byte[] hash = decode(encoded, separator + 1, HASH_LENGTH);
        String canonical = encode(salt, hash);
        if (!canonical.equals(encoded)) {
            throw invalidCredential();
        }
        return new ValuePassword(canonical, salt, hash);
    }

    /**
     * Check a candidate against this credential without creating a new salt.
     *
     * @param candidate candidate plaintext password
     * @return whether it matches
     */
    public boolean verify(String candidate) {
        if (candidate == null) {
            throw DbException.getInvalidValueException("password", "null");
        }
        byte[] actual = derive(candidate, salt);
        boolean matches = Utils.compareSecure(actual, hash);
        Arrays.fill(actual, (byte) 0);
        return matches;
    }

    @Override
    public int compareTypeSafe(Value v, CompareMode mode, CastDataProvider provider) {
        return value.compareTo(((ValuePassword) v).value);
    }

    private static byte[] derive(String plaintext, byte[] salt) {
        // String.getBytes() replaces an unmatched surrogate, which could make
        // different inputs (such as "?" and an unmatched surrogate) identical.
        for (int i = 0; i < plaintext.length(); i++) {
            char c = plaintext.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (++i == plaintext.length() || !Character.isLowSurrogate(plaintext.charAt(i))) {
                    throw DbException.getInvalidValueException("password", "invalid Unicode");
                }
            } else if (Character.isLowSurrogate(c)) {
                throw DbException.getInvalidValueException("password", "invalid Unicode");
            }
        }
        // getPBKDF2 clears its password argument, so give it temporary UTF-8 bytes.
        return SHA256.getPBKDF2(plaintext.getBytes(StandardCharsets.UTF_8), salt,
                ITERATIONS, HASH_LENGTH);
    }

    private static String encode(byte[] salt, byte[] hash) {
        return PREFIX + StringUtils.convertBytesToHex(salt) + '$'
                + StringUtils.convertBytesToHex(hash);
    }

    private static byte[] decode(String encoded, int start, int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            int hi = Character.digit(encoded.charAt(start + i * 2), 16);
            int lo = Character.digit(encoded.charAt(start + i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw invalidCredential();
            }
            bytes[i] = (byte) (hi << 4 | lo);
        }
        return bytes;
    }

    private static DbException invalidCredential() {
        return DbException.getInvalidValueException("PASSWORD credential", "invalid format");
    }
}
