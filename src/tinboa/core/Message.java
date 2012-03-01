
package tinboa.core;

import java.io.Serializable;

/**
 *  @author Yann Le Gall
 * ylegall@gmail.com
 *
 *  @author tony
 *  Jan 27, 2010 9:53:23 AM
 */
public class Message implements Serializable {

    public String message;
    public ServerAction action;
    public UserToken token;
    public boolean success;
    private final int messageNumber;
    private byte[] fileKey;

    public Message(String message, int messageNumber) {
        this(message, ServerAction.NONE, null, messageNumber);
    }

    public Message(String message, ServerAction action, UserToken token, int messageNumber) {
        this.message = message;
        this.action = action;
        this.token = token;
        this.messageNumber = messageNumber;
    }

    public void setKey(byte[] k) {
        fileKey = k;
    }

    public byte[] getKey() {
       return fileKey;
    }

    /**
     * Gets the message number of this message
     * @return
     */
    public int getMessageNumber() {
        return messageNumber;
    }

    /**
     * An enum to indicate the action the server should take.
     * the first 4 messages (0-3) do not require a signature verification.
     */
    public static enum ServerAction {
        NONE,       // 0
        GET_TOKEN,  // 1
        GET_KEY,    // 2
        ADD_GROUP,
        RM_GROUP,
        ADD_USER,
        RM_USER,
        ADD_GROUP_MEM,
        RM_GROUP_MEM,
        LIST_GROUPS,
        LIST_MEM,
        CHANGE_PASS,
        REQUEST_KEY,
        DELETE_KEY,
    }
}
