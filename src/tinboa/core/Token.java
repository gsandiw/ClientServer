
package tinboa.core;

import java.util.List;

/**
 *  @author Yann Le Gall
 *  ylegall@gmail.com
 *  Jan 26, 2010 8:34:45 PM
 */
public final class Token implements UserToken
{
    private List<String> groupList;
    private String issuer;
    private String subject;
    private String fileServer;
    private byte[] signature;

    public Token(String issuer, String subject, String fileServer, List<String> groupList) {
        this.issuer = issuer;
        this.subject = subject;
        this.groupList = groupList;
        this.fileServer = fileServer;
        this.signature = null;
    }

    public final List<String> getGroups() {
        return groupList;
    }

    public final String getIssuer() {
        return issuer;
    }

    public final String getSubject() {
        return subject;
    }

    /**
     * Gets the bytes representing this token and
     * its fields.
     * @return
     */
    public final byte[] getBytes() {
        return new StringBuilder(subject).append(issuer).append(groupList.toString()).append(fileServer).toString().getBytes();
    }
    
    public final void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public final byte[] getSignature() {
        return signature;
    }

    /**
     * Gets the name of the FileServer
     * with which this Token may be used.
     * @return the hostname of the FileServer
     */
    public final String getFileServer() {
        return fileServer == null ? "null" : fileServer;
    }

//    public final void setServer(String serverName){
//        this.fileServer = serverName;
//    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("issuer = ");
        sb.append(issuer);
        sb.append(", subject = ").append(subject);
        sb.append(", groups = ").append((groupList == null)? "[]" : groupList.toString());
        sb.append(", file-server = ").append(fileServer);
        return sb.toString();
    }
    
}
