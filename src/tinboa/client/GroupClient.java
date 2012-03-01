package tinboa.client;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import tinboa.core.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import javax.crypto.SealedObject;
import static tinboa.core.Message.ServerAction;

/**
 *  @author Yann Le Gall
 *  ylegall@gmail.com
 *  Jan 27, 2010 10:00:25 AM
 */
public class GroupClient implements GroupClientInterface
{

    private Socket socket;
    private ObjectOutputStream output;
    private ObjectInputStream input;
    private SecurityManager securityManager;
    private int messageCounter;

    public GroupClient() {
        securityManager = SecurityManager.getInstance();
    }

    public boolean addUserToGroup(String user, String group, UserToken token) {
        return sendMessage(new Message(String.format("%s,%s", user, group), ServerAction.ADD_GROUP_MEM, token, messageCounter++));
    }

    /**
     * Connects to the group server.
     * @param server the hostname.
     * @param port the port.
     * @return true on success, false otherwise.
     */
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

    public boolean createGroup(String groupname, UserToken token) {
        return sendMessage(new Message(groupname, ServerAction.ADD_GROUP, token, messageCounter++));
    }

    public boolean createUser(String username, UserToken token) {
        return sendMessage(new Message(username, ServerAction.ADD_USER, token, messageCounter++));
    }

    public boolean deleteGroup(String groupname, UserToken token) {
        return sendMessage(new Message(groupname, ServerAction.RM_GROUP, token, messageCounter++));
    }

    public boolean deleteUser(String username, UserToken token) {
        return sendMessage(new Message(username, ServerAction.RM_USER, token, messageCounter++));
    }

    public boolean deleteUserFromGroup(String user, String group, UserToken token) {
        return sendMessage(new Message(String.format("%s,%s", user, group), ServerAction.RM_GROUP_MEM, token, messageCounter++));
    }

    public boolean changePass(String oldPass, String newPass, UserToken token) {
        return sendMessage(new Message(String.format("%s,%s", oldPass, newPass), ServerAction.CHANGE_PASS, token, messageCounter++));
    }

    public boolean delete(String fname, UserToken token, String uname, String pass, String hostname) {
        return sendMessage(new Message(uname+","+pass+","+hostname+","+fname, ServerAction.DELETE_KEY, token, messageCounter++));
    }

    public byte[] getKey(String fname, UserToken token, String group, String uname, String hostname, String pass) throws IOException, ClassNotFoundException {
        Message m = new Message(uname + "," + pass + "," + hostname + "," + fname + "," + group, ServerAction.REQUEST_KEY, token, messageCounter++);
        // send the message to the server:
        //output.writeObject(m);
        output.writeObject(securityManager.encryptMessage(m));

        // get a message back, and see if it succeeded.
        //m = (Message) input.readObject();
        m = securityManager.decryptMessage((SealedObject) input.readObject());

        //System.out.println("message=" + m.message);

        if(m.success)
            return m.getKey();
        //else
        return null;
    }

    /**
     * disconnects from the group server.
     */
    public void disconnect() {
        try {
            if (socket == null || socket.isClosed()) {
                return;
            } else {
                Message m = new Message("logout", ServerAction.NONE, null, messageCounter++);
                //output.writeObject(m);
                output.writeObject(securityManager.encryptMessage(m));
                socket.close();
            }
        } catch (Exception e) {
            System.err.println("group-client: " + e);
        }
    }

    
    public void backUpKey(){
        securityManager.backUpKey();
    }

    /**
     * Attempts to obtain a public RSA key from a group server.
     * The key is checked against a recorded key.
     * If there is no saved key, or if the key does not match
     * the saved key, the user is prompted to accept/deny the
     * key.
     * @param hostName
     * @return true if the key matches or if the user accepts the
     * new key, false otherwise.
     */
    public boolean getPublicKey(String hostName) {

        HexString hex = new HexString();

        try {
            // send the message to the server:
            Message m = new Message(hostName, ServerAction.GET_KEY, null, messageCounter++);
            output.writeObject(m);

            // get a message back, report any errors:
            m = (Message) input.readObject();
            if (!m.success) {
                System.out.println(m.message);
                return false;
            }

            // re-build the public key from the byte[] stored in the message:
            Token t = (Token) m.token;
            KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(t.getSignature()));
            GroupServerRecord record = new GroupServerRecord(hostName, publicKey);

            // check if we recognize this server and key:
            if (!securityManager.isKnownGroupServer(record)) {


                // TODO: Here we should send an encrypted challenge to the
                // GroupServer before even asking if the user wants to
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
                    securityManager.setGroupKey(hostName, publicKey);
                } else {
                    // fail if the user does not trust this key:
                    return false;
                }
            }

            // this code runs if we trust the server:
            // generate client's random number
            byte[] serverKeyPart = hex.toByteArray(m.message);
            byte[] clientKeyPart = securityManager.getRandom(32);
            securityManager.setGroupSessionKey(serverKeyPart, clientKeyPart);

            // encrypt this with the public RSA key of the file Server!
            clientKeyPart = securityManager.encrypSessionKey(clientKeyPart, true);

            // send client's random number:
            m.message = hex.toHexString(clientKeyPart);
            output.writeObject(m);

            // get a message back, report any errors:
            m = securityManager.decryptMessage((SealedObject)input.readObject());
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

    /**
     * Gets a token from the server.
     * @param username The current user.
     * @return a token representing the users privileges,
     * or null in case of error.
     */
    public UserToken getToken(String username, String password, String fileHostName) {
        // combine the username and fileHostName: username,fileHostName
        return getToken(username.concat((fileHostName == null)? "": ","+fileHostName), password);
    }

    /**
     * Gets a token from the server.
     * @param username The current user.
     * @return a token representing the users privileges,
     * or null in case of error.
     */
    public UserToken getToken(String username, String password) {
        try {
            // send the message to the server:
            String[] strings = username.split(",");
            Message m = new Message(
                    String.format("%s,%s,%s", strings[0], password, ( strings.length > 1)? strings[1] : ""),
                    ServerAction.GET_TOKEN,
                    null,
                    messageCounter++);
            //output.writeObject(m);
            output.writeObject(securityManager.encryptMessage(m));

            // get a message back, and see if it succeeded.
            //m = (Message) input.readObject();

            if(m.token != null)
                System.out.println(m.token);

            m = securityManager.decryptMessage((SealedObject) input.readObject());
            if (!m.success) {
                // if it did not succeed, say why:
                System.out.println(m.message);
            }

            return m.token;
        } catch (Exception e) {
            System.err.println(e);
            return null;
        }
    }

    /**
     * Lists the members belonging to an owner's group
     * @param group The group.
     * @param token The owner's token.
     * @return A List of members, or null in case of error.
     */
    public List<String> listMembers(String group, UserToken token) {
        try {
            // send the message to the server:
            Message m = new Message(group, ServerAction.LIST_MEM, token, messageCounter++);
            //output.writeObject(m);
            output.writeObject(securityManager.encryptMessage(m));

            // get a message back, and see if it succeeded.
            //m = (Message) input.readObject();
            m = securityManager.decryptMessage((SealedObject) input.readObject());
            if (!m.success) {
                // if it did not succeed, say why:
                System.out.println(m.message);
                return null;
            }

            // split the message by commas:
            List<String> members = new ArrayList<String>();
            String[] mems = m.message.split(",+");
            for (String s : mems) {
                members.add(s);
            }
            return members;

        } catch (Exception e) {
            System.err.println(e);
            return null;
        }
    }

    /**
     * Lists the set of groups to which a user belongs.
     * @param token The owner's token.
     * @return A List of groups, or null in case of error.
     */
    public List<String> listGroups(UserToken token) {
        try {
            // send the message to the server:
            Message m = new Message(null, ServerAction.LIST_GROUPS, token, messageCounter++);
            //output.writeObject(m);
            output.writeObject(securityManager.encryptMessage(m));

            // get a message back, and see if it succeeded.
            //m = (Message) input.readObject();
            m = securityManager.decryptMessage((SealedObject) input.readObject());
            if (!m.success) {
                // if it did not succeed, say why:
                System.out.println(m.message);
                return null;
            }

            // split the message by commas:
            List<String> groups = new ArrayList<String>();

            // quick fix for the empty group problem:
            if (m.message.equals("")) {
                return groups;
            }

            String[] mems = m.message.split(",+");
            for (String s : mems) {
                groups.add(s);
            }
            return groups;

        } catch (Exception e) {
            System.err.println(e);
            return null;
        }
    }

    /**
     * this method is a convenience method which can
     * be used to send a generic request to the
     * server for some action.
    */
    private final boolean sendMessage(Message m) {
        try {

            // send the message to the server:
            //output.writeObject(m);
            output.writeObject(securityManager.encryptMessage(m));

            // get a message back, and see if it succeeded.
            //m = (Message) input.readObject();
            m = securityManager.decryptMessage((SealedObject) input.readObject());
            System.out.println(m.message); // print the response

            return m.success;

        } catch (Exception e) {
            System.err.println(e);
            return false;
        }
    }
}
