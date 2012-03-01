package tinboa.core;

import java.io.Serializable;

/**
 *
 * @author tony
 */
public class FileMessage implements Serializable {

    public String message;      // command for client, return message for server
    public ServerAction action;
    public boolean success;
    public UserToken token;
    private int messageNumber;

    public FileMessage(int messageNumber) {
        this(null, ServerAction.NONE, null, messageNumber);
    }

    public FileMessage(String message, ServerAction action, UserToken token, int messageNumber) { // ideal for upload command
        this.message = message;
        this.action = action;
        this.token = token;
        this.success = false;
        this.messageNumber = messageNumber;
    }

    public int getMessageNumber() {
        return messageNumber;
    }

    public static enum ServerAction
    {
        NONE,       // 0
        GET_KEY,    // 1
//        AES_KEY,    // 2
        DOWNLOAD,
        UPLOAD,
        DELETE,
        LIST
    }
}
