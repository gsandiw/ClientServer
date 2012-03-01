package tinboa.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.URL;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import javax.crypto.SealedObject;
import tinboa.core.Message;
import java.security.Security;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCERSAPrivateKey;
import org.bouncycastle.jce.provider.JCERSAPublicKey;

import tinboa.core.Token;
import tinboa.core.UserToken;

/**
 *
 * @author tony
 * @author Ylegall
 */
public final class SecurityManager
{
    private SecureRandom random;
    private KeyPair RSAKeyPair;
    private Signature signature;
    private Cipher RSAcipher;
    private static final SecurityManager instance = new SecurityManager();

    public static final SecurityManager getInstance() {
        return instance;
    }

    private SecurityManager() {

        Security.addProvider(new BouncyCastleProvider());

        try {
            random = SecureRandom.getInstance("SHA1PRNG");
            signature = Signature.getInstance("RSA", "BC");
            RSAcipher = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BC");
            
            // try to load a key pair
            loadRSAKeys();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * Utility function to run a SHA-1 digest.
     * @param input The input to be hashed.
     * @return the byte[] containing the
     * output of the hash.
     */
    public static final byte[] digest(byte[] input) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-1", "BC");
            return md.digest(input);
        } catch (Exception ex) {
            return input;
        }
    }

    /**
     * Gets a number of random bytes
     * usin a strong crpto algorithm.
     * @return
     */
    public byte[] getRandom(int size) {
        return random.generateSeed(size);
    }

    /**
     * Gets the RSA public key belonging to
     * this GroupServer.
     * @return the PublicKey
     */
    final PublicKey getPublicKey() {
        return this.RSAKeyPair.getPublic();
    }

    /**
     * Signs a token with using this server's private key.
     * @param t The Token to sign
     */
    final void signToken(Token t) {
        try {
            signature.initSign(RSAKeyPair.getPrivate(), random);
            signature.update(digest(t.getBytes()));
            t.setSignature(signature.sign());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Encrypts a serializable using the secret AES key
     * and returns a sealed object.
     * @param <T> the type of the message (Message, FileMessage)
     * @param message the message to be encrypted.
     * @return a SealedObject to be passed to the server.
     */
    final <T extends Serializable> SealedObject encryptMessage(T message, Cipher AEScipher) {
        try {
            return new SealedObject(message, AEScipher);
        } catch (Exception e) {
            System.err.println(e);
            return null;
        }
    }

    /**
     * Decrypts an incomming SealedObject into a message.
     * @param o The SealedObject to decrypt
     * @return A decrypted Message object
     */
    final Message decryptMessage(SealedObject o, Cipher AEScipher) {
        try {
            return (Message) o.getObject(AEScipher);
        } catch (Exception e) {
            System.err.println(e);
            return null;
        }
    }

    /**
     * Decrypts the session key sent by
     * the client using the private RSA key
     * @param bytes
     * @return the decrypted bytes, or the original
     * bytes on error.
     */
    final byte[] decryptSessionKey(byte[] bytes) {
        try {
            RSAcipher.init(Cipher.DECRYPT_MODE, RSAKeyPair.getPrivate());
            return RSAcipher.doFinal(bytes);
        } catch (Exception e) {
            //System.err.println(e.getMessage());
            e.printStackTrace();
            return bytes;
        }
    }

    /**
     * this function generates new RSA keys whenever
     * no stored keys are detected. The new keys are
     * saved to a resource file.
     */
    private final void makeRSAKeys(File pubKey, File privKey) {

        try {
            // create the keys:
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            generator.initialize(512, random);
            RSAKeyPair = generator.generateKeyPair();

            // save public Key to file
            FileOutputStream fos = new FileOutputStream(pubKey);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(RSAKeyPair.getPublic());
            oos.close();

            // save public Key to file
            fos = new FileOutputStream(privKey);
            oos = new ObjectOutputStream(fos);
            oos.writeObject(RSAKeyPair.getPrivate());
            oos.close();

        } catch (Exception e) {
            System.err.println(e);
            e.printStackTrace();
        }
    }

    /**
     * Unwraps an AESKey using the private RSA key
     * @param key
     * @return true if everything was ok, false on error.
     */
    final Key unwrapAESKey(byte[] key) throws Exception{
        RSAcipher.init(Cipher.UNWRAP_MODE, RSAKeyPair.getPrivate());
        return RSAcipher.unwrap(key, "AES", Cipher.SECRET_KEY);
    }

    /**
     * loads the RSA keys from resource files.
     * if the resource files are not found,
     * a new RSA key pair is generated and
     * saved to a new resource file.
     */
    private final void loadRSAKeys() {
        try {
            File pubFile, privFile;
            String name = GroupServer.getHostName();
            System.out.println("*** DEBUG: hostname: "+name);
            URL url1, url2;

            // try to find the resource file:
            url1 = SecurityManager.class.getResource("/tinboa/server/" + name + "_publicKey.ser");
            url2 = SecurityManager.class.getResource("/tinboa/server/" + name + "_privateKey.ser");
            if(url1 == null || url2 == null) {
                url1 = SecurityManager.class.getResource("/tinboa/server/");
                pubFile = new File(url1.getPath() + name + "_publicKey.ser");
                privFile = new File(url1.getPath() + name + "_privateKey.ser");
                makeRSAKeys(pubFile, privFile); //create or overwrite a file
            } else {
                // load the public Key
                pubFile = new File(url1.getFile());
                FileInputStream fis = new FileInputStream(pubFile);
                ObjectInputStream ois = new ObjectInputStream(fis);
                PublicKey publicKey = (JCERSAPublicKey)ois.readObject();
                ois.close();

                // load the private Key
                pubFile = new File(url2.getFile());
                fis = new FileInputStream(pubFile);
                ois = new ObjectInputStream(fis);
                PrivateKey privateKey = (JCERSAPrivateKey)ois.readObject();
                ois.close();

                RSAKeyPair = new KeyPair(publicKey, privateKey);

            }
        } catch (Exception e) {
            //System.err.println(e);
            e.printStackTrace();
        }
    }

    /**
     * Verifies the signature on the specified token.
     * Checks that the token has not been modified and
     * that it was generated by the GroupServer.
     * @param t
     * @return true if the signature is valid, false otherwise.
     */
    final boolean verifyTokenSignature(UserToken t) {
        try {
            Token token = (Token) t;
            signature.initVerify(RSAKeyPair.getPublic());
            signature.update(digest(token.getBytes()));
            return signature.verify(token.getSignature());
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
