/*
 * Copyright 2004-2026 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (https://h2database.com/html/license.html).
 * Initial Developer: H2 Group
 */
package org.h2.test.unit;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.h2.message.DbException;
import org.h2.security.BlockCipher;
import org.h2.security.CipherFactory;
import org.h2.security.SHA256;
import org.h2.security.SHA3;
import org.h2.test.TestBase;
import org.h2.util.StringUtils;
import org.h2.value.ValuePassword;

/**
 * Tests various security primitives.
 */
public class TestSecurity extends TestBase {

    /**
     * Run just this test.
     *
     * @param a ignored
     */
    public static void main(String... a) throws Exception {
        TestBase.createCaller().init().testFromMain();
    }

    @Override
    public void test() throws SQLException {
        testConnectWithHash();
        testPassword();
        testSHA();
        testSHA3();
        testAES();
        testBlockCiphers();
    }

    private void testPassword() throws SQLException {
        String plaintext = "päss\uD83D\uDD11'\\word";
        ValuePassword first = ValuePassword.get(plaintext);
        ValuePassword second = ValuePassword.get(plaintext);
        assertTrue(first.verify(plaintext));
        assertFalse(first.verify("Päss\uD83D\uDD11'\\word"));
        assertFalse(first.verify("wrong"));
        assertFalse(first.getString().contains(plaintext));
        assertFalse(first.equals(second));
        assertFalse(first.getString().equals(second.getString()));
        ValuePassword restored = ValuePassword.fromEncoded(first.getString());
        assertEquals(first, restored);
        assertEquals(first.hashCode(), restored.hashCode());
        assertTrue(restored.verify(plaintext));
        assertTrue(ValuePassword.get("").verify(""));
        assertTrue(ValuePassword.get(first.getString()).verify(first.getString()));
        assertThrows(DbException.class, () -> ValuePassword.fromEncoded("bad"));
        assertThrows(DbException.class, () -> ValuePassword.fromEncoded(
                first.getString().replace("600000", "1")));
        assertThrows(DbException.class, () -> ValuePassword.fromEncoded(
                first.getString().substring(0, first.getString().length() - 1)));
        assertThrows(DbException.class, () -> ValuePassword.get(null));
        assertThrows(DbException.class, () -> ValuePassword.get("\uD800"));
        assertThrows(DbException.class, () -> first.verify("\uDC00"));

        // Check the production record against Java's independent PBKDF2 implementation.
        ValuePassword ascii = ValuePassword.get("known password");
        String[] fields = ascii.getString().split("\\$");
        assertEquals("h2p", fields[1]);
        assertEquals("1", fields[2]);
        assertEquals("pbkdf2-sha256", fields[3]);
        assertEquals("600000", fields[4]);
        PBEKeySpec spec = new PBEKeySpec("known password".toCharArray(),
                StringUtils.convertHexToBytes(fields[5]), 600_000, 256);
        try {
            assertEquals(fields[6], StringUtils.convertBytesToHex(
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded()));
        } catch (Exception e) {
            throw new AssertionError(e);
        } finally {
            spec.clearPassword();
        }

        try (Connection conn = DriverManager.getConnection("jdbc:h2:mem:password");
                Statement stat = conn.createStatement()) {
            stat.execute("CREATE TABLE P (ID INT PRIMARY KEY, C PASSWORD)");
            try (PreparedStatement prep = conn.prepareStatement("INSERT INTO P VALUES (?, ?)")) {
                prep.setInt(1, 1);
                prep.setString(2, plaintext);
                prep.executeUpdate();
                prep.setInt(1, 2);
                prep.setString(2, plaintext);
                prep.executeUpdate();
            }
            try (ResultSet rs = stat.executeQuery("SELECT C FROM P ORDER BY ID")) {
                rs.next();
                String firstStored = rs.getString(1);
                assertFalse(firstStored.contains(plaintext));
                rs.next();
                assertFalse(firstStored.equals(rs.getString(1)));
            }
            try (PreparedStatement prep = conn.prepareStatement(
                    "SELECT PASSWORD_VERIFY(C, ?) FROM P ORDER BY ID")) {
                prep.setString(1, plaintext);
                try (ResultSet rs = prep.executeQuery()) {
                    assertTrue(rs.next());
                    assertTrue(rs.getBoolean(1));
                    assertTrue(rs.next());
                    assertTrue(rs.getBoolean(1));
                }
            }
            stat.executeUpdate("UPDATE P SET C = (SELECT C FROM P WHERE ID = 1) WHERE ID = 2");
            try (ResultSet rs = stat.executeQuery("SELECT C FROM P ORDER BY ID")) {
                rs.next();
                String firstStored = rs.getString(1);
                rs.next();
                assertEquals(firstStored, rs.getString(1));
            }
            stat.executeUpdate("INSERT INTO P SELECT 3, C FROM P WHERE ID = 1");
            try (PreparedStatement prep = conn.prepareStatement("SELECT C = (SELECT C FROM P WHERE ID = 1), "
                    + "PASSWORD_VERIFY(C, ?) FROM P WHERE ID = 3")) {
                prep.setString(1, plaintext);
                try (ResultSet rs = prep.executeQuery()) {
                    rs.next();
                    assertTrue(rs.getBoolean(1));
                    assertTrue(rs.getBoolean(2));
                }
            }
            stat.executeUpdate("INSERT INTO P VALUES (4, 'repeat'), (5, 'repeat')");
            try (ResultSet rs = stat.executeQuery("SELECT COUNT(DISTINCT C) FROM P WHERE ID IN (4, 5)")) {
                rs.next();
                assertEquals(2, rs.getInt(1));
            }
            stat.executeUpdate("INSERT INTO P SELECT X + 5, CAST('cast-repeat' AS PASSWORD) "
                    + "FROM SYSTEM_RANGE(1, 3)");
            try (ResultSet rs = stat.executeQuery("SELECT COUNT(DISTINCT C) FROM P WHERE ID BETWEEN 6 AND 8")) {
                rs.next();
                assertEquals(3, rs.getInt(1));
            }
            try (ResultSet rs = stat.executeQuery("SELECT PASSWORD_VERIFY(NULL, 'x'), "
                    + "PASSWORD_VERIFY((SELECT C FROM P WHERE ID = 1), NULL)")) {
                rs.next();
                assertNull(rs.getObject(1));
                assertNull(rs.getObject(2));
            }
            stat.executeUpdate("UPDATE P SET C = 'changed' WHERE ID = 1");
            try (ResultSet rs = stat.executeQuery("SELECT PASSWORD_VERIFY(C, 'changed'), "
                    + "PASSWORD_VERIFY(C, 'CHANGED') FROM P WHERE ID = 1")) {
                rs.next();
                assertTrue(rs.getBoolean(1));
                assertFalse(rs.getBoolean(2));
            }
            stat.executeUpdate("INSERT INTO P VALUES (9, NULL)");
            try (ResultSet rs = stat.executeQuery("SELECT C FROM P WHERE ID = 9")) {
                rs.next();
                assertNull(rs.getObject(1));
            }
            assertThrows(SQLException.class,
                    () -> stat.executeQuery("SELECT PASSWORD_VERIFY('not a credential', 'x')"));
        }
    }

    private static void testConnectWithHash() throws SQLException {
        Connection conn = DriverManager.getConnection(
                "jdbc:h2:mem:test", "sa", "sa");
        String pwd = StringUtils.convertBytesToHex(
                SHA256.getKeyPasswordHash("SA", "sa".toCharArray()));
        Connection conn2 = DriverManager.getConnection(
                "jdbc:h2:mem:test;PASSWORD_HASH=TRUE", "sa", pwd);
        conn.close();
        conn2.close();
    }

    private void testSHA() {
        testPBKDF2();
        testHMAC();
        testOneSHA();
    }

    private void testPBKDF2() {
        // test vectors from StackOverflow (PBKDF2-HMAC-SHA2)
        assertEquals(
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
                StringUtils.convertBytesToHex(
                SHA256.getPBKDF2(
                "password".getBytes(),
                "salt".getBytes(), 1, 32)));
        assertEquals(
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
                StringUtils.convertBytesToHex(
                SHA256.getPBKDF2(
                "password".getBytes(),
                "salt".getBytes(), 2, 32)));
        assertEquals(
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
                StringUtils.convertBytesToHex(
                SHA256.getPBKDF2(
                "password".getBytes(),
                "salt".getBytes(), 4096, 32)));
        // take a very long time to calculate
        // assertEquals(
        //         "cf81c66fe8cfc04d1f31ecb65dab4089f7f179e" +
        //         "89b3b0bcb17ad10e3ac6eba46",
        //         StringUtils.convertBytesToHex(
        //         SHA256.getPBKDF2(
        //         "password".getBytes(),
        //         "salt".getBytes(), 16777216, 32)));
        assertEquals(
                "348c89dbcbd32b2f32d814b8116e84cf2b17347e" +
                "bc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
                StringUtils.convertBytesToHex(
                SHA256.getPBKDF2(
                ("password" + "PASSWORD" + "password").getBytes(),
                ("salt"+ "SALT"+ "salt"+ "SALT"+ "salt"+
                "SALT"+ "salt"+ "SALT"+ "salt").getBytes(), 4096, 40)));
        assertEquals(
                "89b69d0516f829893c696226650a8687",
                StringUtils.convertBytesToHex(
                SHA256.getPBKDF2(
                "pass\0word".getBytes(),
                "sa\0lt".getBytes(), 4096, 16)));

        // the password is filled with zeroes
        byte[] password = "Test".getBytes();
        SHA256.getPBKDF2(password, "".getBytes(), 1, 16);
        assertEquals(new byte[4], password);
    }

    private void testHMAC() {
        // from Wikipedia
        assertEquals(
                "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
                StringUtils.convertBytesToHex(
                        SHA256.getHMAC(new byte[0], new byte[0])));
        assertEquals(
                "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
                StringUtils.convertBytesToHex(
                SHA256.getHMAC(
                "key".getBytes(),
                "The quick brown fox jumps over the lazy dog".getBytes())));
    }

    private String getHashString(byte[] data) {
        byte[] result = SHA256.getHash(data, true);
        if (data.length > 0) {
            assertEquals(0, data[0]);
        }
        return StringUtils.convertBytesToHex(result);
    }

    private void testOneSHA() {
        assertEquals(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                getHashString(new byte[] {}));
        assertEquals(
                "68aa2e2ee5dff96e3355e6c7ee373e3d6a4e17f75f9518d843709c0c9bc3e3d4",
                getHashString(new byte[] { 0x19 }));
        assertEquals(
                "175ee69b02ba9b58e2b0a5fd13819cea573f3940a94f825128cf4209beabb4e8",
                getHashString(
                        new byte[] { (byte) 0xe3, (byte) 0xd7, 0x25,
                        0x70, (byte) 0xdc, (byte) 0xdd, 0x78, 0x7c,
                        (byte) 0xe3, (byte) 0x88, 0x7a, (byte) 0xb2,
                        (byte) 0xcd, 0x68, 0x46, 0x52 }));
        checkSHA256(
                "",
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
        checkSHA256(
                "a",
                "CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB");
        checkSHA256(
                "abc",
                "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
        checkSHA256(
                "message digest",
                "F7846F55CF23E14EEBEAB5B4E1550CAD5B509E3348FBC4EFA3A1413D393CB650");
        checkSHA256(
                "abcdefghijklmnopqrstuvwxyz",
                "71C480DF93D6AE2F1EFAD1447C66C9525E316218CF51FC8D9ED832F2DAF18B73");
        checkSHA256(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1");
        checkSHA256(
                "123456789012345678901234567890" +
                        "12345678901234567890" +
                        "123456789012345678901234567890",
                "F371BC4A311F2B009EEF952DD83CA80E2B60026C8E935592D0F9C308453C813E");
        StringBuilder buff = new StringBuilder(1000000);
        buff.append('a');
        checkSHA256(buff.toString(),
                "CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB");
    }

    private void checkSHA256(String message, String expected) {
        String hash = StringUtils.convertBytesToHex(
                SHA256.getHash(message.getBytes(), true)).toUpperCase();
        assertEquals(expected, hash);
    }

    private void testSHA3() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-224");
            Random r = new Random();
            byte[] bytes1 = new byte[r.nextInt(1025)];
            byte[] bytes2 = new byte[256];
            r.nextBytes(bytes1);
            r.nextBytes(bytes2);
            testSHA3(md, SHA3.getSha3_224(), bytes1, bytes2);
            testSHA3(MessageDigest.getInstance("SHA3-256"), SHA3.getSha3_256(), bytes1, bytes2);
            testSHA3(MessageDigest.getInstance("SHA3-384"), SHA3.getSha3_384(), bytes1, bytes2);
            testSHA3(MessageDigest.getInstance("SHA3-512"), SHA3.getSha3_512(), bytes1, bytes2);
        } catch (NoSuchAlgorithmException e) {
            // Java 8 doesn't support SHA-3
        }
    }

    private void testSHA3(MessageDigest md1, SHA3 md2, byte[] bytes1, byte[] bytes2) {
        md1.update(bytes1);
        md2.update(bytes1);
        md1.update(bytes2, 0, 1);
        md2.update(bytes2, 0, 1);
        md1.update(bytes2, 1, 33);
        md2.update(bytes2, 1, 33);
        md1.update(bytes2, 34, 222);
        md2.update(bytes2, 34, 222);
        assertEquals(md1.digest(), md2.digest());
        md1.update(bytes2, 1, 1);
        md2.update(bytes2, 1, 1);
        assertEquals(md1.digest(), md2.digest());
    }

    private void testBlockCiphers() {
        for (String algorithm : new String[] { "AES", "FOG" }) {
            byte[] test = new byte[4096];
            BlockCipher cipher = CipherFactory.getBlockCipher(algorithm);
            cipher.setKey("abcdefghijklmnop".getBytes());
            for (int i = 0; i < 10; i++) {
                cipher.encrypt(test, 0, test.length);
            }
            assertFalse(isCompressible(test));
            for (int i = 0; i < 10; i++) {
                cipher.decrypt(test, 0, test.length);
            }
            assertEquals(new byte[test.length], test);
            assertTrue(isCompressible(test));
        }
    }

    private void testAES() {
        BlockCipher test = CipherFactory.getBlockCipher("AES");

        String r;
        byte[] data;

        // test vector from
        // http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip
        // ECBVarTxt128e.txt
        // COUNT = 0
        test.setKey(StringUtils.convertHexToBytes("00000000000000000000000000000000"));
        data = StringUtils.convertHexToBytes("80000000000000000000000000000000");
        test.encrypt(data, 0, data.length);
        r = StringUtils.convertBytesToHex(data);
        assertEquals("3ad78e726c1ec02b7ebfe92b23d9ec34", r);

        // COUNT = 127
        test.setKey(StringUtils.convertHexToBytes("00000000000000000000000000000000"));
        data = StringUtils.convertHexToBytes("ffffffffffffffffffffffffffffffff");
        test.encrypt(data, 0, data.length);
        r = StringUtils.convertBytesToHex(data);
        assertEquals("3f5b8cc9ea855a0afa7347d23e8d664e", r);

        // test vector
        test.setKey(StringUtils.convertHexToBytes("2b7e151628aed2a6abf7158809cf4f3c"));
        data = StringUtils.convertHexToBytes("6bc1bee22e409f96e93d7e117393172a");
        test.encrypt(data, 0, data.length);
        r = StringUtils.convertBytesToHex(data);
        assertEquals("3ad77bb40d7a3660a89ecaf32466ef97", r);

        test.setKey(StringUtils.convertHexToBytes("000102030405060708090A0B0C0D0E0F"));
        byte[] in = new byte[128];
        byte[] enc = new byte[128];
        test.encrypt(enc, 0, 128);
        test.decrypt(enc, 0, 128);
        if (!Arrays.equals(in, enc)) {
            throw new AssertionError();
        }

        for (int i = 0; i < 10; i++) {
            test.encrypt(in, 0, 128);
            test.decrypt(enc, 0, 128);
        }
    }

    private static boolean isCompressible(byte[] data) {
        int len = data.length;
        int[] sum = new int[16];
        for (int i = 0; i < len; i++) {
            int x = (data[i] & 255) >> 4;
            sum[x]++;
        }
        int r = 0;
        for (int x : sum) {
            long v = ((long) x << 32) / len;
            r += 63 - Long.numberOfLeadingZeros(v + 1);
        }
        return len * r < len * 120;
    }

}
