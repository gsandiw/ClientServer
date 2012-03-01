/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package tinboa.core;

import java.security.Key;
import java.util.List;

/**
 *
 * @author gep19
 */
public class PassToken implements UserToken {

    private List<String> groupList;
    private String issuer;
    private String subject;
    private String fileServer;
    private byte[] signature;
    private List<Key> keys;

    public PassToken(String issuer, String subject, List<Key> groupKeys, List<String> groupList) {
        this.issuer = issuer;
        this.subject = subject;
        this.groupList = groupList;
        this.signature = null;
        this.keys = groupKeys;
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

    public final Key getKey(String groupName){
        int index = 0;
        index = groupList.indexOf(groupName);
        return keys.get(index);
    }
}
