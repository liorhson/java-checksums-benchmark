
package com.github.yoshaul;

import fr.cryptohash.Digest;
import fr.cryptohash.MD5;
import fr.cryptohash.SHA1;
import fr.cryptohash.SHA256;
import org.openjdk.jmh.annotations.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.concurrent.TimeUnit;

/**
 * JMH based benchmark for common digest algorithms using different implementation.
 *
 * @author Yossi Shaul
 */
@State(value = Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@Fork(2)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 5, time = 5, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 2, time = 2, timeUnit = TimeUnit.SECONDS)
public class ChecksumsCalculationBenchmark {

    private static ByteArrayInputStream bis;

    @Benchmark
    public void javaMd5() throws IOException, NoSuchAlgorithmException {
        calcJava("md5", bis);
    }

    @Benchmark
    public void javaSha1() throws IOException, NoSuchAlgorithmException {
        calcJava("sha1", bis);
    }

    @Benchmark
    public void javaSha256() throws IOException, NoSuchAlgorithmException {
        calcJava("sha-256", bis);
    }

    @Benchmark
    public void saphirMd5() throws IOException, NoSuchAlgorithmException {
        calcSaphir("md5", bis);
    }

    @Benchmark
    public void saphirSha1() throws IOException, NoSuchAlgorithmException {
        calcSaphir("sha1", bis);
    }

    @Benchmark
    public void saphirSha256() throws IOException, NoSuchAlgorithmException {
        calcSaphir("sha-256", bis);
    }

    @Benchmark
    public void bouncyCastleMd5() throws IOException, NoSuchAlgorithmException {
        calcBc("md5", bis);
    }

    @Benchmark
    public void bouncyCastleSha1() throws IOException, NoSuchAlgorithmException {
        calcBc("sha1", bis);
    }

    @Benchmark
    public void bouncyCastleSha256() throws IOException, NoSuchAlgorithmException {
        calcBc("sha-256", bis);
    }

    private void calcJava(String alg, InputStream is) throws IOException, NoSuchAlgorithmException {
        dig(new JavaDigester(alg), is);
    }

    private void calcSaphir(String alg, InputStream is) throws IOException {
        dig(new SaphirDigester(alg), is);
    }

    private void calcBc(String alg, InputStream is) throws IOException {
        dig(new BcDigester(alg), is);
    }

    private void dig(Digester dig, InputStream is) throws IOException {
        byte[] buf = new byte[1024];
        int n;
        while ((n = is.read(buf)) > -1) {
            dig.update(buf, 0, n);
        }
        hex(dig.digest());
        is.reset();
    }

    private String hex(byte[] bytes) {
        // Encodes a byte array into a String that should be the length of the type (2 chars per byte)
        StringBuilder sb = new StringBuilder();
        for (byte aBinaryData : bytes) {
            String t = Integer.toHexString(aBinaryData & 0xff);
            if (t.length() == 1) {
                sb.append("0");
            }
            sb.append(t);
        }
        String result = sb.toString();
        //System.out.println(result);
        return result;
    }

    @Setup
    public void generateRandomBytes() {
        // System.out.println("GENERATING RANDOM");
        byte[] bytes = new byte[1024*1024];
        new Random().nextBytes(bytes);
        bis = new ByteArrayInputStream(bytes);
    }

    private interface Digester {
        void update(byte[] buf, int off, int len);
        byte[] digest();
    }

    private final class JavaDigester implements Digester {
        private final MessageDigest dig;
        JavaDigester(String alg) throws NoSuchAlgorithmException {
            dig = MessageDigest.getInstance(alg);
        }

        @Override public void update(byte[] buf, int off, int len) {
            dig.update(buf, off, len);
        }

        @Override public byte[] digest() {
            return dig.digest();
        }
    }

    private final class SaphirDigester implements Digester {
        private final Digest dig;
        SaphirDigester(String alg) {
            switch (alg) {
                case "md5": dig = new MD5(); break;
                case "sha1": dig = new SHA1(); break;
                case "sha-256": dig = new SHA256(); break;
                default: throw new IllegalArgumentException("Unexpected alg: " + alg);
            }
        }

        @Override public void update(byte[] buf, int off, int len) {
            dig.update(buf, off, len);
        }

        @Override public byte[] digest() {
            return dig.digest();
        }
    }

    private final class BcDigester implements Digester {
        private final MessageDigest dig;
        BcDigester(String alg) {
            switch (alg) {
                case "md5": dig = new org.bouncycastle.jcajce.provider.digest.MD5.Digest(); break;
                case "sha1": dig = new org.bouncycastle.jcajce.provider.digest.SHA1.Digest(); break;
                case "sha-256": dig = new org.bouncycastle.jcajce.provider.digest.SHA256.Digest(); break;
                default: throw new IllegalArgumentException("Unexpected alg: " + alg);
            }
        }

        @Override public void update(byte[] buf, int off, int len) {
            dig.update(buf, off, len);
        }

        @Override public byte[] digest() {
            return dig.digest();
        }
    }
}
