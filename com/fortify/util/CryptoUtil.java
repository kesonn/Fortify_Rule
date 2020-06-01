//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.fortify.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class CryptoUtil {
    private static final String MESSAGE_DIGEST_ALGORITHM = "SHA-1";
    private static final String CRYPTO_PROVIDER = "SUN";
    private static final int BUFFER_SIZE = 262144;
    private static final String STD = "1fea047f-dee0ac89-b5db25a6-b0c3a4cf";

    public CryptoUtil() {
    }

    public static MessageDigest getMessageDigestAlgorithm() {
        try {
            return MessageDigest.getInstance("SHA-1", "SUN");
        } catch (GeneralSecurityException var1) {
            throw new RuntimeException(var1);
        }
    }

    public static byte[] makeDigest(InputStream inStream) throws IOException {
        return makeDigest(inStream, getMessageDigestAlgorithm());
    }

    public static byte[] makeDigest(InputStream inStream, MessageDigest md) throws IOException {
        byte[] buffer = new byte[262144];
        md.reset();
        DigestInputStream in = new DigestInputStream(inStream, md);

        while(in.read(buffer) != -1) {
        }

        in.close();
        return md.digest();
    }

    private static void encrypt(long[] v, long[] k) {
        long y = v[0];
        long z = v[1];
        long sum = 0L;
        long delta = 2654435769L;
        long n = 32L;

        for(long top = 4294967295L; n-- > 0L; z &= top) {
            sum += delta;
            sum &= top;
            y += (z << 4) + k[0] ^ z + sum ^ (z >> 5) + k[1];
            y &= top;
            z += (y << 4) + k[2] ^ y + sum ^ (y >> 5) + k[3];
        }

        v[0] = y;
        v[1] = z;
    }

    private static void decrypt(long[] v, long[] k) {
        long n = 32L;
        long y = v[0];
        long z = v[1];
        long delta = 2654435769L;
        long top = 4294967295L;
        long sum = delta << 5;

        for(sum &= top; n-- > 0L; sum &= top) {
            z -= (y << 4) + k[2] ^ y + sum ^ (y >> 5) + k[3];
            z &= top;
            y -= (z << 4) + k[0] ^ z + sum ^ (z >> 5) + k[1];
            y &= top;
            sum -= delta;
        }

        v[0] = y;
        v[1] = z;
    }

    private static void enc(InputStream source, OutputStream dest, long[] usrKey) throws IOException {
        long[] k = (long[])((long[])usrKey.clone());
        byte[] byteBuf = new byte[8];
        byte[] tail = new byte[]{32, 32, 32, 32, 32, 32, 32, 8};
        long[] unsigned32Buf = new long[2];
        long top = 4294967295L;

        int bytesRead;
        while((bytesRead = source.read(byteBuf)) != -1) {
            if (bytesRead < 8) {
                tail[7] = (byte)bytesRead;
            }

            byteArrayToUnsigned32(byteBuf, unsigned32Buf);
            encrypt(unsigned32Buf, k);
            k[0] = k[0] + 17L & top;
            k[1] = k[1] + 17L & top;
            k[2] = k[2] + 17L & top;
            k[3] = k[3] + 17L & top;
            unsigned32ToByteArray(unsigned32Buf, byteBuf);
            dest.write(byteBuf);
        }

        byteArrayToUnsigned32(tail, unsigned32Buf);
        encrypt(unsigned32Buf, k);
        k[0] = k[0] + 17L & top;
        k[1] = k[1] + 17L & top;
        k[2] = k[2] + 17L & top;
        k[3] = k[3] + 17L & top;
        unsigned32ToByteArray(unsigned32Buf, tail);
        dest.write(tail);
    }

    private static void dec(InputStream source, OutputStream dest, long[] usrKey) throws IOException {
        long[] k = (long[])((long[])usrKey.clone());
        byte[] byteBuf = new byte[8];
        byte[] byteBufDelay = null;
        long[] unsigned32Buf = new long[2];
        long top = 4294967295L;

        int bytesRead;
        while((bytesRead = source.read(byteBuf)) != -1) {
            if (bytesRead < 8) {
                throw new IOException("invalid encrypted stream");
            }

            byteArrayToUnsigned32(byteBuf, unsigned32Buf);
            decrypt(unsigned32Buf, k);
            k[0] = k[0] + 17L & top;
            k[1] = k[1] + 17L & top;
            k[2] = k[2] + 17L & top;
            k[3] = k[3] + 17L & top;
            unsigned32ToByteArray(unsigned32Buf, byteBuf);
            if (source.available() == 0) {
                int bytesToWrite = byteBuf[7];
                if (bytesToWrite > 8 || bytesToWrite < 0 || byteBufDelay == null) {
                    throw new IOException("invalid encrypted stream");
                }

                dest.write(byteBufDelay, 0, bytesToWrite);
            }

            if (byteBufDelay != null) {
                dest.write(byteBufDelay, 0, 8);
                byte[] t = byteBufDelay;
                byteBufDelay = byteBuf;
                byteBuf = t;
            } else {
                byteBufDelay = byteBuf;
                byteBuf = new byte[8];
            }
        }

    }

    private static void doBlockCipher(InputStream source, OutputStream dest, boolean encrypt, long[] usrKey) throws IOException {
        if (encrypt) {
            enc(source, dest, usrKey);
        } else {
            dec(source, dest, usrKey);
        }

    }

    public static Properties readHeaders(InputStream encrypted) throws IOException {
        Properties props = new Properties();
        final PushbackInputStream src = new PushbackInputStream(encrypted);
        props.load(new InputStream() {
            boolean closed = false;

            public int read() throws IOException {
                if (this.closed) {
                    return -1;
                } else {
                    int c = src.read();
                    if (c == 0) {
                        src.unread(c);
                        this.closed = true;
                        return -1;
                    } else {
                        return c;
                    }
                }
            }
        });
        int read = src.read();
        if (read != 0) {
            throw new IOException("invalid encrypted stream");
        } else {
            return props;
        }
    }

    public static InputStream decryptCompressedAfterHeaders(InputStream encrypted, String keyString) throws IOException {
        return decryptAfterHeaders(encrypted, keyString, true);
    }

    public static InputStream decryptAfterHeaders(InputStream encrypted, String keyString, boolean compressed) throws IOException {
        long[] key = makeKeyFromString(keyString != null ? keyString : "1fea047f-dee0ac89-b5db25a6-b0c3a4cf");
        ByteArrayOutputStream cleartext = new ByteArrayOutputStream();
        doBlockCipher(encrypted, cleartext, false, key);
        cleartext.close();
        byte[] bytes = cleartext.toByteArray();
        if (compressed) {
            bytes = uncompressString(bytes);
        }

        return new ByteArrayInputStream(bytes);
    }

    public static InputStream decryptCompressed(InputStream encrypted, String keyString) throws IOException {
        readHeaders(encrypted);
        return decryptCompressedAfterHeaders(encrypted, keyString);
    }

    public static void encryptAndCompress(InputStream cleartext, OutputStream ciphertext, String keyString, Properties properties) throws IOException {
        if (properties != null) {
            properties.store(ciphertext, (String)null);
        }

        ciphertext.write(new byte[]{0});
        encryptAfterHeaders(cleartext, ciphertext, keyString, true);
    }

    public static void encryptAfterHeaders(InputStream stream, OutputStream ciphertext, String keyString, boolean compress) throws IOException {
        long[] key = makeKeyFromString(keyString != null ? keyString : "1fea047f-dee0ac89-b5db25a6-b0c3a4cf");
        if (compress) {
            stream = compressInputStream(stream);
        }

        doBlockCipher(stream, ciphertext, true, key);
        stream.close();
    }

    private static long[] makeKeyFromString(String keyString) {
        long[] k = new long[4];
        String[] splitString = new String[4];
        StringTokenizer st = new StringTokenizer(keyString, "-");

        int i;
        for(i = 0; i < splitString.length; ++i) {
            if (!st.hasMoreTokens()) {
                throw new Error("invalid key");
            }

            splitString[i] = st.nextToken();
        }

        for(i = 0; i < 4; ++i) {
            try {
                k[i] = Long.parseLong(splitString[i], 16);
            } catch (NumberFormatException var6) {
                throw new Error("invalid key");
            }
        }

        return k;
    }

    private static byte[] uncompressString(byte[] in) throws IOException {
        GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(in));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int bufferSize = 10240;
        byte[] buffer = new byte[bufferSize];

        while(true) {
            int bytesRead = gis.read(buffer, 0, bufferSize);
            if (bytesRead == -1) {
                return out.toByteArray();
            }

            out.write(buffer, 0, bytesRead);
        }
    }

    private static InputStream compressInputStream(InputStream in) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        GZIPOutputStream gz = new GZIPOutputStream(baos);
        int bufferSize = 10240;
        byte[] buffer = new byte[bufferSize];
        int var5 = 0;

        while(true) {
            int bytesRead = in.read(buffer, 0, bufferSize);
            if (bytesRead == -1) {
                gz.close();
                return new ByteArrayInputStream(baos.toByteArray());
            }

            gz.write(buffer, 0, bytesRead);
            var5 += bytesRead;
        }
    }

    public static void byteArrayToUnsigned32(byte[] byteBuf, long[] unsigned32Buf) {
        for(int i = 0; i < unsigned32Buf.length; ++i) {
            unsigned32Buf[i] = ((long)byteBuf[i * 4] & 255L) + (((long)byteBuf[i * 4 + 1] & 255L) << 8) + (((long)byteBuf[i * 4 + 2] & 255L) << 16) + (((long)byteBuf[i * 4 + 3] & 255L) << 24);
        }

    }

    public static void unsigned32ToByteArray(long[] unsigned32Buf, byte[] byteBuf) {
        for(int i = 0; i < unsigned32Buf.length; ++i) {
            long l = unsigned32Buf[i];
            byteBuf[i * 4 + 0] = (byte)((int)(l >> 0 & 255L));
            byteBuf[i * 4 + 1] = (byte)((int)(l >> 8 & 255L));
            byteBuf[i * 4 + 2] = (byte)((int)(l >> 16 & 255L));
            byteBuf[i * 4 + 3] = (byte)((int)(l >> 24 & 255L));
            if (byteBuf[i * 4 + 0] > 127) {
                byteBuf[i * 4 + 0] = (byte)(byteBuf[i * 4 + 0] - 256);
            }

            if (byteBuf[i * 4 + 1] > 127) {
                byteBuf[i * 4 + 1] = (byte)(byteBuf[i * 4 + 1] - 256);
            }

            if (byteBuf[i * 4 + 2] > 127) {
                byteBuf[i * 4 + 2] = (byte)(byteBuf[i * 4 + 2] - 256);
            }

            if (byteBuf[i * 4 + 3] > 127) {
                byteBuf[i * 4 + 3] = (byte)(byteBuf[i * 4 + 3] - 256);
            }
        }

    }
}
