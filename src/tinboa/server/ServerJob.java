package tinboa.server;

import java.io.EOFException;
import tinboa.core.*;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import static tinboa.core.Message.ServerAction;

/**
 * This class encapsulates the core operations that
 * occur when a client makes a connection to the server:
 * 
 * <ol>
 * <li>After connecting, the client sends a message
 * which contains an operation code (ServerAction).</li>
 * <li>The the appropriate Database method is called.</li>
 * <li>A response message is sent back to the client.</li>
 *</ol>
 *
 * This class is run on a separate thread to allow
 * the serve to handle multiple connections.
 *
 *  @author Yann Le Gall
 *  ylegall@gmail.com
 *  Jan 27, 2010 1:02:49 AM
 */
public class ServerJob implements Runnable
{

    private Socket socket;
    private Database database;
    private Key AESKey;
    private IvParameterSpec iv;
    private Cipher AEScipher;
    private int messageCounter;
    private SecurityManager securityManager;
    private ObjectInputStream input;
    private ObjectOutputStream output;
    private boolean validSession;

    protected ServerJob(Socket socket) {
        messageCounter = 0;
        validSession = true;
        this.socket = socket;
        database = Database.getInstance();
        securityManager = SecurityManager.getInstance();
        try {
            AEScipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        } catch (Exception e) {
            System.err.println(e);
        }
    }

    /**
     * The main loop of the server-client thread.
     * TODO: encrypt/decrypt messages
     * http://java.sun.com/developer/technicalArticles/ALT/serialization/
     * http://tirl.org/blogs/media-lab-blog/47/
     */
    public void run() {
        try {
            // Print incoming message
            System.out.println("*** DEBUG: New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " **");

            // set up I/O streams with the client
            input = new ObjectInputStream(socket.getInputStream());
            output = new ObjectOutputStream(socket.getOutputStream());

            // Loop to read messages
            Message msg = null;
            do {

                // read an object from the ObjectInputStream
                // and decrypt it if we've establised a key:
                if (AESKey == null) {
                    msg = (Message) input.readObject();
                } else {
                    AEScipher.init(Cipher.DECRYPT_MODE, AESKey, iv);
                    msg = securityManager.decryptMessage((SealedObject) input.readObject(), AEScipher);
                }

                System.out.print("*** DEBUG: Received message: ");
                System.out.println(String.format("\t%s %s, # %d", msg.message, msg.action.name(), msg.getMessageNumber()));

                // check the counter on this message
                if (msg.getMessageNumber() != messageCounter++) {
                    System.out.println("received message number: " + msg.getMessageNumber() + ", expecting: " + messageCounter);
                    break;
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

    // this method checks the action on the message
    // and instructs the Database class to perform
    // the desired task. The message fields are
    // modified to indicate success/failure.
    private final void processMessage(final Message msg) {

        ServerAction action = msg.action;

        // see Message.ServerAction:
        // only check the signature if the action
        // is greater than 2
        if (action.ordinal() > 2) {

            // check the signature. if the check fails,
            // don't perform any operations.
            if (!securityManager.verifyTokenSignature(msg.token)) {
                msg.success = false;
                msg.message = "invalid user token. try logging on again.";
                return;
            }
        }

        switch (action) {
            case NONE:
                msg.success = true;
                return;
            case ADD_GROUP:
                database.createGroup(msg);
                break;
            case RM_GROUP:
                database.deleteGroup(msg);
                break;
            case ADD_USER:
                database.createUser(msg);
                break;
            case RM_USER:
                database.deleteUser(msg);
                break;
            case ADD_GROUP_MEM:
                database.addUserToGroup(msg);
                break;
            case RM_GROUP_MEM:
                database.deleteUserFromGroup(msg);
                break;
            case LIST_GROUPS:
                database.listGroups(msg);
                break;
            case LIST_MEM:
                database.listMembers(msg);
                break;
            case GET_TOKEN:
                database.getToken(msg);
                break;
            case GET_KEY:
                sendPublicKey(msg);
                break;
            case CHANGE_PASS:
                database.changePass(msg);
                break;
            case REQUEST_KEY:
                database.getKey(msg, securityManager);
                break;
            case DELETE_KEY:
                // TODO: Should this method exist?
                database.delKey(msg);
                break;
            default:
        }
    }

    // here we store the public RSA key in the message
    // using the signature field.
    // the server should also send the hostname
    private final void sendPublicKey(Message msg) {

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
            msg = (Message) input.readObject();
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

        } catch (Exception e) {
            e.printStackTrace();
            msg.success = false;
        }
    }
}
