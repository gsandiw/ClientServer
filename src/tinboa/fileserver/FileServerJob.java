package tinboa.fileserver;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import tinboa.core.FileMessage;
import tinboa.core.FileMessage.ServerAction;
import tinboa.core.HexString;
import tinboa.core.Token;

/**
 *
 * @author Yann Le Gall
 * @author Tony Blatt
 * ylegall@gmail.com
 * @date Feb 4, 2010
 */
public class FileServerJob implements Runnable
{

    private Socket socket;
    private FileManager fileManager;
    private Key AESKey;
    private IvParameterSpec iv;
    private Cipher AEScipher;
    private int messageCounter;
    private ObjectInputStream input;
    private ObjectOutputStream output;
    private boolean validSession;
    fSecurityManager securityManager;

    protected FileServerJob(Socket socket) {
        messageCounter = 0;
        validSession = true;
        this.socket = socket;
        fileManager = FileManager.getInstance();
        securityManager = fSecurityManager.getInstance();
        try {
            AEScipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            //AEScipher = Cipher.getInstance("AES/CBC/NoPadding", "BC");
        } catch (Exception e) {
            System.err.println(e);
        }
    }

    public void run() {
        try {
            // Print incoming message
            System.out.println("*** DEBUG: New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " **");

            // set up I/O streams with the client
            input = new ObjectInputStream(socket.getInputStream());
            output = new ObjectOutputStream(socket.getOutputStream());

            // Loop to read messages
            FileMessage msg = null;
            do {

                // read an object from the ObjectInputStream
                // and decrypt it if we've establised a key:
                if (AESKey == null) {
                    msg = (FileMessage) input.readObject();
                } else {
                    AEScipher.init(Cipher.DECRYPT_MODE, AESKey, iv);
                    msg = securityManager.decryptFileMessage((SealedObject) input.readObject(), AEScipher);
                }

                System.out.print("*** DEBUG: Received message: ");
                System.out.println(String.format("\t%s %s, # %d", msg.message, msg.action.name(), msg.getMessageNumber()));

                // check the counter on this message
                if (msg.getMessageNumber() != messageCounter++) {
                    System.out.println("received message number: " + msg.getMessageNumber() + ", expecting: " + messageCounter);
                    continue; // maybe break?
                }
                if (msg.message != null && msg.message.equals("logout")) {
                    break;
                }

                // perform an action based on the message.
                // the fields of the message may be modified:
                processMessage(msg);

                // send response
                if (AESKey == null) {
                    output.writeObject(msg);
                } else {
                    AEScipher.init(Cipher.ENCRYPT_MODE, AESKey, iv);
                    output.writeObject(securityManager.encryptMessage(msg, AEScipher));
                }

                // initiate file transfer here:
                if (msg.success) {
                    if (msg.action == FileMessage.ServerAction.DOWNLOAD) {
                        sendFile(msg, output);
                    } else if (msg.action == FileMessage.ServerAction.UPLOAD) {
                        getFile(msg, input);
                    }
                }

            } while (validSession);

            // Close and cleanup
            System.out.println("*** DEBUG: Closing connection with " + socket.getInetAddress());
            socket.close();

        } catch (EOFException eof) {
            System.out.println("client connection closed.");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    private final void processMessage(final FileMessage msg) throws UnknownHostException {

        ServerAction action = msg.action;

        // see FileMessage.ServerAction:
        // only check the signature if the action
        // is greater than 1
        if (action.ordinal() > 1) {

            Token temp = (Token) msg.token;
            if (!temp.getFileServer().equals(FileServer.getHostName())) {
                validSession = false;
            }

            // check the signature. if the check fails,
            // don't perform any operations.
            if (!securityManager.verifyTokenSignature(msg.token)) {
                securityManager.loadGroupServerkeys();
                if (!securityManager.verifyTokenSignature(msg.token)) {
                    msg.success = false;
                    msg.message = "unrecognized group server token";
                    return;
                }
            }
        }

        switch (action) {

            case NONE:
                msg.success = true;
                return;
            case UPLOAD:
                fileManager.uploadFile(msg);
                break;
            case DOWNLOAD:
                fileManager.downloadFile(msg);
                break;
            case LIST:
                fileManager.listFiles(msg);
                break;
            case DELETE:
                fileManager.deleteFile(msg);
                break;
            case GET_KEY:
                sendPublicKey(msg);
                break;
            default:
        }
    }

    // decrypts an incoming file from the client. The cipher input
    // stream is initialized with the AES cipher in decrypt mode.
    private final void getFile(FileMessage m, InputStream input) {

        try {
            FileOutputStream fout = new FileOutputStream(".filedata/" + m.message);
            BufferedOutputStream bout = new BufferedOutputStream(fout);
            AEScipher.init(Cipher.DECRYPT_MODE, AESKey, iv);
            CipherInputStream cis = new CipherInputStream(input, AEScipher);

            int len;
            byte[] buffer = new byte[128];
            len = cis.read(buffer);
            while (len > 0) {
                bout.write(buffer, 0, len);
                len = cis.read(buffer);
            }
            bout.flush();
            bout.close();

        } catch (Exception e) {
            System.err.println(e);
        }
    }

    // sends the file specified in FileMessage to the requesting client
    // encrypts the file using a CipherOutputStream initialized with
    // the AES cipher
    private final void sendFile(FileMessage m, final ObjectOutputStream out) {
        try {
            File file = new File(".filedata/" + m.message);
            long length = file.length();

            // first send the length of the file:
            out.writeLong(length);
            out.flush();

            FileInputStream fin = new FileInputStream(file);
            BufferedInputStream bin = new BufferedInputStream(fin);

            // initialized the cipher and cipher stream:
            AEScipher.init(Cipher.ENCRYPT_MODE, AESKey, iv);

            int len;
            byte[] buffer = new byte[128];
            while ((len = bin.read(buffer)) > 0) {
                //out.write(buffer, 0, len);
                out.write(AEScipher.update(buffer, 0, len));
            }

            // call do final manually to avoid
            // closing the socket's stream:
            out.write(AEScipher.doFinal());

            out.flush();
            bin.close();

        } catch (Exception e) {
            System.err.println(e);
        }
    }

//    // sends the file specified in FileMessage to the requesting client
//    // encrypts the file using a CipherOutputStream initialized with
//    // the AES cipher
//    private final void sendFile(FileMessage m, final ObjectOutputStream out) {
//        try {
//            File file = new File(".filedata/" + m.message);
//            long remaining = file.length();
//
//            // first send the remaining of the file:
//            out.writeLong(remaining);
//            out.flush();
//
//            FileInputStream fin = new FileInputStream(file);
//            BufferedInputStream bin = new BufferedInputStream(fin);
//
//            // initialized the cipher and cipher stream:
//            AEScipher.init(Cipher.ENCRYPT_MODE, AESKey, iv);
//            CipherOutputStream cout = new CipherOutputStream(socket.getOutputStream(), AEScipher);
//
//            int len = -1;
//            byte[] buffer = new byte[64];
//
//            while(remaining > 0) {
//
//                len = bin.read(buffer);
//                if(len < 0) break;
//
////                // add padding to fill up the last block
////                if(remaining < buffer.length) {
////                   while(len < buffer.length) {
////                        buffer[len++] = (byte)' ';
////                   }
////                    //cout.write(AEScipher.doFinal(buffer));
////                    break;
////                }
//                cout.write(buffer, 0, len);
//                remaining -= len;
//            }
//
//            // call doFinal() manually to avoid
//            // closing the socket's stream:
//            out.write(AEScipher.doFinal());
//
//            out.flush();
//            bin.close();
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
    // here we store the public RSA key in the message
    // using the signature field.
    // the server should also send the hostname
    private final void sendPublicKey(FileMessage msg) {

        try {

            // first send the RSA public key
            // and the random number
            HexString hex = new HexString();
            Token t = new Token(null, null, null, null);
            t.setSignature(securityManager.getPublicKey().getEncoded());
            msg.token = t;
            byte[] serverKeyPart = securityManager.getRandom(32);
            msg.message = hex.toHexString(serverKeyPart);
            msg.success = true;
            output.writeObject(msg);

            // read in the Random number sent by the client
            // and rebuild the AES key:
            msg = (FileMessage) input.readObject();
            byte[] clientKeyPart = hex.toByteArray(msg.message);

            // decrypt the client's random number with the RSA key
            clientKeyPart = securityManager.decryptSessionKey(clientKeyPart);
            
//            byte[] seed = new byte[64];
//            for (int i = 0; i < seed.length; i++) {
//                seed[i] = (byte) (serverKeyPart[i] ^ clientKeyPart[i]);
//            }

            byte[] seed = new byte[64];
            System.arraycopy(serverKeyPart, 0, seed, 0, serverKeyPart.length);
            System.arraycopy(clientKeyPart, 0, seed, serverKeyPart.length, clientKeyPart.length);

            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(seed);

            // generate a 128-bit AES key:
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
            keyGen.init(128, random);
            AESKey = keyGen.generateKey();

            // generate the IV:
            byte[] IV = new byte[16];
            random.nextBytes(IV);
            iv = new IvParameterSpec(IV);
            serverKeyPart = null;
            msg.success = true;

        } catch (Exception e) {
            msg.success = false;
        }
    }
}
