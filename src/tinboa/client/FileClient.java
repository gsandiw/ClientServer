package tinboa.client;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.File;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import tinboa.core.*;
import java.util.List;
import java.util.Scanner;
import javax.crypto.SealedObject;
import tinboa.core.FileMessage;
import static tinboa.core.FileMessage.ServerAction;

/**
 *  @author Yann Le Gall
 *  ylegall@gmail.com
 *  Jan 27, 2010 10:07:01 AM
 */
public class FileClient implements FileClientInterface {

    private Socket socket;
    private ObjectOutputStream output;
    private ObjectInputStream input;
    private SecurityManager securityManager;
    private int messageCounter;

    public FileClient() {
        securityManager = SecurityManager.getInstance();
    }

    public boolean connect(String server, int port) {
        try {
            messageCounter = 0;
            socket = new Socket(server, port);
            output = new ObjectOutputStream(socket.getOutputStream());
            input = new ObjectInputStream(socket.getInputStream());
            return socket.isConnected();
        } catch (Exception e) {
            System.err.println(e);
            return false;
        }
    }

    /**
     * Attempts to obtain a public RSA key from a file server.
     * The key is checked against a recorded key.
     * If there is no saved key, or if the key does not match
     * the saved key, the user is prompted to accept/deny the
     * key.
     * @param hostName
     * @return true if the key matches or if the user accepts the
     * new key, false otherwise.
     */
    public boolean getFileKey(String hostName) {

        HexString hex = new HexString();

        try {
            // send the message to the server:
            FileMessage m = new FileMessage(hostName, ServerAction.GET_KEY, null, messageCounter++);
            output.writeObject(m);

            // get a message back, report any errors:
            m = (FileMessage) input.readObject();
            if (!m.success) {
                System.out.println(m.message);
                return false;
            }

            // re-build the public key from the byte[] stored in the message:
            Token t = (Token) m.token;
            KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(t.getSignature()));
            FileServerRecord record = new FileServerRecord(hostName, publicKey);

            // check if we recognize this server and key:
            if (!securityManager.isKnownFileServer(record)) {


                // TODO: Here we should send an encrypted challenge to the
                // FileServer before even asking if the user wants to
                // accept:


                // ask if the user trusts the finger print of the
                // of the received public key:
                System.out.println(String.format(
                        "\nThe public key of host '%s' does not match current records.", hostName));

                String s = hex.toHexFingerprint(SecurityManager.digest(publicKey.getEncoded()));
                System.out.println(String.format("The RSA key fingerprint is\n %s", s));
                System.out.print("Do you want to accept this key and continue (y/n)? ");
                s = new Scanner(System.in).next();
                if (s.equalsIgnoreCase("y") || s.equalsIgnoreCase("yes")) {
                    securityManager.addFileServerKey(hostName, publicKey);
                } else {
                    // fail if the user does not trust this key:
                    return false;
                }
            }

            // this code runs if we trust the server:
            // generate client's random number
            byte[] serverKeyPart = hex.toByteArray(m.message);
            byte[] clientKeyPart = securityManager.getRandom(32);
            securityManager.setFileSessionKey(serverKeyPart, clientKeyPart);

            // encrypt this with the public RSA key of the file Server!
            clientKeyPart = securityManager.encrypSessionKey(clientKeyPart, false);

            // send client's random number:
            m.message = hex.toHexString(clientKeyPart);
            output.writeObject(m);

            // get a message back, report any errors:
            m = securityManager.decryptFileMessage((SealedObject)input.readObject());
            if (!m.success) {
                System.out.println(m.message);
                return false;
            }

        } catch (Exception e) {
            System.err.println("here: " + e);
            e.printStackTrace();
            return false;
        }

        return true;
    }

//    /**
//     * Sends the encrypted AES key
//     * and IV to the group server.
//     * @return true if the operation succeeded
//     * false, otherwise.
//     */
//    final String sendAESKey() {
//        try {
//
//            // get our key and IV from the securityManager:
//            byte[] IV = securityManager.getIV();
//            byte[] keyBytes = securityManager.getEncryptedAESKey(securityManager.getFileServerKey());
//
//            // send the Key & IV as a String in the message
//            HexString hex = new HexString();
//            String hexString = hex.toHexString(keyBytes) + ',' + hex.toHexString(IV);
//
//            FileMessage msg = new FileMessage(hexString, ServerAction.AES_KEY, null, messageCounter++);
//            output.writeObject(msg);
//
//            msg = securityManager.decryptFileMessage((SealedObject) input.readObject());
//            if(msg.success)
//                return msg.message;
//            // else
//            return null;
//
//        } catch (ClassNotFoundException ex) {
//            System.err.println(ex);
//            return null;
//        } catch (IOException ioe) {
//            System.err.println(ioe);
//            return null;
//        }
//    }

    /**
     * 
     * @return
     */
    public final boolean isConnected() {
        return (socket != null && socket.isConnected());
    }

    //checks to see if the user owns the file
    //if they don't tell the user that they are not authorized to do so
    //if they are, delete the file
    public boolean delete(String filename, UserToken token) {
        FileMessage m = new FileMessage(filename, ServerAction.DELETE, token, messageCounter++);
        try {
            // send the message to the server:
            //output.writeObject(m);
            output.writeObject(securityManager.encryptMessage(m));

            // get a message back, and see if it succeeded.
            //m = (FileMessage) input.readObject();
            m = securityManager.decryptFileMessage((SealedObject)input.readObject());
            System.out.println(m.message);  // print the response
            return m.success;

        } catch (Exception e) {
            System.err.println(e);
            return false;
        }
    }

    public void disconnect() {
        try {
            if (socket == null || socket.isClosed()) {
                return;
            } else {
                FileMessage m = new FileMessage("logout", ServerAction.NONE, null, messageCounter++);
                //output.writeObject(m);
                output.writeObject(securityManager.encryptMessage(m));
                socket.close();
            }
        } catch (Exception e) {
            System.err.println(e);
        }
    }

    //Checks to see if the user is able to download the file (if they are in the group)
    //If they are in the group send them the file in the desired location
    public boolean download(String sourceFile, String destFile, UserToken token, GroupClient gclient, String uname, String hostname, String pass) {
        try {
            byte[] key = gclient.getKey(sourceFile, token, "", uname, hostname, pass);
            if(key == null)
                return false; // the user does not have access to the file
            // send the message to the server:
            FileMessage m = new FileMessage(sourceFile, ServerAction.DOWNLOAD, token, messageCounter++);
            //output.writeObject(m);
            output.writeObject(securityManager.encryptMessage(m));

            // get a message back, and see if it succeeded.
            //m = (FileMessage) input.readObject();
            m = securityManager.decryptFileMessage((SealedObject)input.readObject());
            if (!m.success) {
                // if it did not succeed, say why:
                System.out.println(m.message);
                return false;
            }

            // download from socket into destination file:
            System.out.print("download started...");
            
            return securityManager.downloadFile(destFile, input, socket.getInputStream(), key);

            /*
            FileOutputStream fout = new FileOutputStream(destFile);
            BufferedOutputStream bout = new BufferedOutputStream(fout);

            // get the length of the file:
            long length = input.readLong();

            int len;
            byte[] buffer = new byte[128];
            while (length > 0) {
                len = input.read(buffer);
                if(len <= 0) {break;}
                bout.write(buffer, 0, len);
                length -= len;
            }
            bout.flush();
            bout.close();
            */

        } catch (Exception e) {
            System.err.println(e);
	    e.printStackTrace();
            return false;
        }
    }

    //based on the user's membership, list each file in the user's groups
    public List<String> listFiles(UserToken token) {
        try {
            // send the message to the server:
            FileMessage m = new FileMessage(null, ServerAction.LIST, token, messageCounter++);
            //output.writeObject(m);
            output.writeObject(securityManager.encryptMessage(m));

            // get a message back, and see if it succeeded.
            //m = (FileMessage) input.readObject();
            m = securityManager.decryptFileMessage((SealedObject)input.readObject());
            if (!m.success) {
                // if it did not succeed, say why:
                System.out.println("here1" + m.message);
                return null;
            }

            // split the message by commas:
            List<String> groups = new ArrayList<String>();
            String[] mems = m.message.split(",+");
            for(String s : mems) {
                if(!s.equals(""))
                    groups.add(s);
            }
            return groups;

        } catch (Exception e) {
            System.out.println("in here");
            System.err.println(e);
            return null;
        }
    }

    public boolean upload(String sourceFile, String destFile, String group, UserToken token, GroupClient gclient, String uname, String hostname, String pass) {
        try {
            byte[] key = gclient.getKey(destFile, token, group, uname, hostname, pass);
            if(key == null)
                return false; // the user does not have access to the file
            
            //System.out.println(String.format("uploading %s to %s", sourceFile, group));
            File file = new File(sourceFile);
            if(file.exists()){
                // send the message to the server:
                FileMessage m = new FileMessage(destFile.concat(",").concat(group), ServerAction.UPLOAD, token, messageCounter++);
                //output.writeObject(m);
                output.writeObject(securityManager.encryptMessage(m));

                // get a message back, and see if it succeeded.
                //m = (FileMessage) input.readObject();
                m = securityManager.decryptFileMessage((SealedObject)input.readObject());
                if (!m.success) {
                    // if it did not succeed, say why:
                    System.out.println(m.message);
                    return false;
                }

                return securityManager.uploadFile(sourceFile, output, key);

//                // upload file to socket from destination file:
//                FileInputStream fin = new FileInputStream(f);
//                BufferedInputStream bin = new BufferedInputStream(fin);
//
//                System.out.print("upload started...");
//
//                int len;
//                byte[] buffer = new byte[128];
//                while((len = bin.read(buffer)) > 0) {
//                    output.write(buffer, 0, len);
//                }
//                output.flush();
//                bin.close();
//                System.out.print("done.");
//                return true;


            } else{
                System.out.println("SRC " + sourceFile + " does not exist.");
                return false;
            }

        } catch (Exception e) {
            System.err.println(e);
            return false;
        }
    }

    public boolean upload(String sourceFile, String destFile, String group, UserToken token) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public boolean download(String sourceFile, String destFile, UserToken token) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
