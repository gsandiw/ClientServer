
package tinboa.server;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import tinboa.core.*;

/**
 * This class will be used to store user/group
 * data during program execution. This class
 * will also persist the state of the system
 * by reading from and writing to flat files
 * containing user/group data.
 *
 *  @author Yann Le Gall
 *  ylegall@gmail.com
 *  Jan 27, 2010 10:42:23 AM
 */
public class Database {

    private static final Database instance;
    private Map<String, UserRecord> userData;
    private Map<String, GroupRecord> groupData;
    private Map<String, FileRecord> fileData; // holds the key, group and name of the file: should be indexed on the "name of the file"

    static {
        instance = new Database();
    }

    private Database() {
        userData = new Hashtable<String, UserRecord>();
        groupData = new Hashtable<String, GroupRecord>();
        fileData = new Hashtable<String, FileRecord>();
        File f = new File(".groupdata/");
        if(!f.exists() || !f.isDirectory()) {
            f.mkdir();
        }
        loadGroupData(".groupdata/.groups");
        loadUserData(".groupdata/.users");
        loadFileData(".groupdata/.files");
    }

    /**
     * Gets the single instance of this database.
     * @return the single Database instance.
     */
    public static final Database getInstance() {
        return instance;
    }

     /**
      * checks to see if the user/password pair is valid, if so,
      * creates a token and stores it in the message.
      */
    final void getToken(Message message) {
        String[] tokens = message.message.split(",");
        String user = tokens[0];
        String pass = tokens[1];
	String fileHostName = (tokens.length > 3)? tokens[2]: "" ;

        HexString hex = new HexString();
        pass = hex.toHexString(SecurityManager.digest(pass.getBytes()));

        UserRecord record = userData.get(user);
        if(record == null) {
            System.out.println("invalid username: "+user);
            message.message = "invalid username.";
            message.success = false;
        } else if(!record.password.equals(pass)) {
            message.message = "invalid password.";
            message.success = false;
        } else {

            // issue and sign a token if everything was OK:
            List<String> list = new ArrayList<String>(record.groups.size());
            list.addAll(record.groups);
            Token t = new Token(GroupServer.getHostName(), user, fileHostName, list);
            SecurityManager.getInstance().signToken(t);
            
            message.token = t;
            message.success = true;
            message.message = "token granted.";
        }
    }


    /**
     * Creates a new user, if the requester is an ADMIN,
     * and if the user does not already exist.
     * @param message
     */
    final void createUser(Message message) {

        String user = message.message;
        UserToken t = message.token;

        // check for ADMIN status:
        if(t.getGroups().contains("ADMIN")) {
            if(!userData.containsKey(user)) {

                // create a random first time password
                String pass = new String(PassManager.createPass());

                // only store the hash of the password
                HexString hex = new HexString();
                message.message = user + "'s password is " + pass;
                pass = hex.toHexString(SecurityManager.digest(pass.getBytes()));

                UserRecord u = new UserRecord(user, pass);
                userData.put(user, u);
                message.success = true;
            } else {
                message.message = "user already exists.";
                message.success = false;
            }
        } else {
            message.message = "user creation requites ADMIN status.";
            message.success = false;
        }
    }

    /**
     * Creates a group, provided that the group does not already exist.
     * @param message
     */
    final void createGroup(Message message) {
        String group = message.message;
        String owner = message.token.getSubject();

        if(groupData.containsKey(group)) {
            message.message = "group already exists.";
            message.success = false;
        } else {
            GroupRecord gr = new GroupRecord(group, owner);
            gr.members.add(owner);
            groupData.put(group, gr);

            // update the user record for the owner:
            UserRecord r = userData.get(owner);
            r.groups.add(group);
            
            message.token.getGroups().add(group);
            message.message = "group created";
            message.success = true;
        }
    }

    /**
     * Removes a group. Only the owner is allowed to remove the group.
     * TODO: make sure that tokens are consistent
     * @param message
     */
    final void deleteGroup(Message message) {
        String groupName = message.message;
        String user = message.token.getSubject();

        if(groupData.containsKey(groupName)) {
            GroupRecord gr = groupData.remove(groupName);
            if(gr.owner.equals(user)) {

                // remove this group from all member records:
                for(String member : gr.members) {
                    userData.get(member).groups.remove(groupName);
                }

                message.message = "group deleted";
                message.success = true;
            } else {
                message.message = "only the group owner may delete the group.";
                message.success = false;
            }
        } else {
            message.message = "group does not exist.";
            message.success = false;
        }
    }

    // deletes a user if the requester is an ADMIN.
    // also removes the use from all groups
    // TODO: make sure that tokens are consistent
    final void deleteUser(Message message) {
        String user = message.message;
        UserToken t = message.token;

        // check for ADMIN status:
        if(t.getGroups().contains("ADMIN")) {
            if(userData.containsKey(user)) {
                UserRecord u = userData.remove(user); // extract the record
                
                // do not delete if user is also an ADMIN
                if(u.groups.contains("ADMIN")) {
                    message.message = "user is an ADMIN.";
                    message.success = false;
                    userData.put(user, u);
                    return;
                }
                Set<String> groups = u.groups;

                // loop over group data, remove user
                Set<String> members;
                for(String group : groups) {
                    GroupRecord gr = groupData.get(group);
                    gr.members.remove(user);

                    // if the user owns the group,
                    // then remove all members, and remove this group
                    if(gr.owner.equals(user)) {
                        members = gr.members;
                        for(String member : members) {
                            userData.get(member).groups.remove(group);
                        }
                        
                        // remove the group:
                        groupData.remove(group);
                    }
                }
                 message.success = true;
                 message.message = "user removed.";

            } else {
                message.message = "user does not exist.";
                message.success = false;
            }
        } else {
            message.message = "user deletion requites ADMIN status.";
            message.success = false;
        }
    }

    /**
     * Allows the owner of a group to add an existing user
     * to the set of group members.
     * @param message
     */
    final void addUserToGroup(Message message) {
        String[] tokens = message.message.split(",");
        String user = tokens[0];
        String group = tokens[1];

        if(groupData.containsKey(group)) {
            GroupRecord gr = groupData.get(group);
            if(gr.owner.equals(message.token.getSubject())) {
                if(userData.containsKey(user)) {
                    UserRecord ur = userData.get(user);
                    ur.groups.add(group);
                    gr.members.add(user);
                    message.message = "user added to group.";
                    message.success = true;
                } else {
                    message.message = "user does not exist.";
                    message.success = false;
                }
            } else {
                message.message = "only the group owner may add members.";
                message.success = false;
            }
        } else {
            message.message = "group does not exist.";
            message.success = false;
        }
    }

    /**
     * Allows a group owner to remove a group member.
     * @param message
     */
    final void deleteUserFromGroup(Message message) {
        String[] tokens = message.message.split(",");
        String user = tokens[0];
        String group = tokens[1];

        if(groupData.containsKey(group)) {
            GroupRecord gr = groupData.get(group);
            if(gr.owner.equals(message.token.getSubject())) {
                if(userData.containsKey(user)) {
                    UserRecord ur = userData.get(user);
                    ur.groups.remove(group);
                    gr.members.remove(user);
                    message.message = "user removed from group.";
                    message.success = true;
                } else {
                    message.message = "user does not exist.";
                    message.success = false;
                }
            } else {
                message.message = "only the group owner may delete members.";
                message.success = false;
            }
        } else {
            message.message = "group does not exist.";
            message.success = false;
        }
    }

    /**
     * lists the members of a group for the group owner.
     * @param message
     */
    final void listMembers(Message message) {
        String groupName = message.message;
        String user = message.token.getSubject();

        if(groupData.containsKey(groupName)) {
            GroupRecord gr = groupData.get(groupName);
            if(gr.owner.equals(user)) {

                StringBuilder sb = new StringBuilder();
                for(String member : gr.members) {
                    sb.append(member).append(',');
                }
                message.message = sb.toString();
                message.success = true;
            } else {
                message.message = "only the group owner may list members.";
                message.success = false;
            }
        } else {
            message.message = "group does not exist.";
            message.success = false;
        }
    }

    /**
     * lists the members of a group for the group owner.
     * @param message
     */
    final void listGroups(Message message) {
        String user = message.token.getSubject();
        UserRecord r = userData.get(user);
        StringBuilder sb = new StringBuilder();

        for(String group : r.groups) {
            sb.append(group).append(',');
        }

        message.message = sb.toString();
        message.success = true;
    }

    /**
     * Changes a user's password.
     * TODO: do a thurough test of this method
     * @param message
     */
    final void changePass(Message message) {
        String[] tokens = message.message.split(",");
        String oldpass = tokens[0];
        String newpass = tokens[1];
        UserRecord rec = userData.get(message.token.getSubject());

        // hash the old password to see if it matches the stored hash:
        HexString hex = new HexString();
        oldpass = hex.toHexString(SecurityManager.digest(oldpass.getBytes()));
        
        if(!rec.password.equals(oldpass)) {
            message.message = "incorrect password. password not changed.";
            message.success = false;
        } else {
            rec.password = hex.toHexString(SecurityManager.digest(newpass.getBytes()));
            message.message = "password changed.";
            message.success = true;
        }
    }

    final void getKey(Message message, SecurityManager secMan) {
        String fkey = message.message;
        String[] tmp = message.message.split(",");
        message.message = tmp[0] + "," + tmp[1] + "," + tmp[2];
        getToken(message);
        Token tok = (Token)message.token;
        List<String> groups = tok.getGroups();
        FileRecord fr = fileData.get(tmp[3]);
        fkey = tmp[3];
        //String[] toks = fkey.split("[,]");
        //fkey = toks[0];
        //if(!groups.contains(toks[1])) { // if the user is not part of the specified group
        if((fr != null) && !groups.contains(fr.groupName)) {
            //System.out.println("System fail code 1");
            message.message = "You are not part of group " + fr.groupName;
            message.success = false;
            return;
        }

        //FileRecord fr = fileData.get(fkey);
        //tmp[4] = group name
        
        if((fr == null) && (tmp.length == 5) && (!tmp[4].equals("")) && (groups.contains(tmp[4]))) { // this is a new file to upload...
            //System.out.println("fail code 2");
            fr = new FileRecord(tmp[3], tmp[4], secMan.getRandom(128));
            fileData.put(fkey, fr);
        }
        if(fr == null) {
            //System.out.println("fail code 3");
            message.setKey(null);
            message.message = "file does not exist";
            message.success = false;
            return;
        }
        message.setKey(fr.fileKey);
        message.message = "key...";
        message.success = true;
    }

    final void delKey(Message message) {
        String fkey = message.message;
        getToken(message);
        Token tok = (Token)message.token;
        List<String> groups = tok.getGroups();
        String[] toks = fkey.split("[,]");
        fkey = toks[toks.length-1];
        FileRecord fr = fileData.get(fkey);
        if(!groups.contains(fr.groupName)) { // if the user is not part of the specified group
            message.message = "You are not part of group " + fr.groupName;
            message.success = false;
            return;
        }

        fileData.remove(fkey);
        message.message = fkey + " has been deleted";
        message.success = true;
    }

    /*
     * This will load the group info in the groupData hashTable
     * The groupMember list will consist of a name (which we have to determine),
     * the owner and the users in the group.
    */
    private void loadGroupData(String fileName) {

        // if the file does not exist,
        // create it and return.
        File f = new File(fileName);
        try {
            if(f.createNewFile()) {
                return;
            }
        }
        catch (java.io.IOException e) {
            System.err.println(e);
            return;
        }

        
        Scanner scanner = null;
        String[] tokens;
        GroupRecord tempRecord; //this is for the loop to add to the list of groups

        try{
             scanner = new Scanner(f);
             while(scanner.hasNextLine()) {

                 // split the line on commas:
                 tokens = scanner.nextLine().split(",");

                 // the 1st string is the groupName, the 2nd is the owner:
                 tempRecord = new GroupRecord(tokens[0], tokens[1]);

                 // add each member to a set of members:
                 for(int i = 2; i < tokens.length; i++) {
                     tempRecord.members.add(tokens[i]);
                 }

                 // add the record to our database:
                 groupData.put(tokens[0], tempRecord);
             }
             
        }
        catch (FileNotFoundException e) {System.err.println(e);}
        finally {
            scanner.close();
        }
    }

    // loads the user data into the userData hashtable
    private void loadUserData(String fileName) {

        Scanner sc = new Scanner(System.in);

        // if the file does not exist,
        // create it.
        File f = new File(fileName);
        try {
            if (f.createNewFile()) {

                // the first time the system is started
                // this will create an ADMIN group
                System.out.println("The database file has not been detected.");
                System.out.println("Please input the name of your Admin:");

                System.out.print("Username: ");
                String newAdmin = sc.next();

                System.out.print("Password: ");
                String pass = sc.next();

                HexString hex = new HexString();
                pass = hex.toHexString(SecurityManager.digest(pass.getBytes()));
                pass = hex.toHexString(SecurityManager.digest(pass.getBytes()));
                
                UserRecord ur = new UserRecord(newAdmin, pass);
                ur.groups.add("ADMIN");
                userData.put(newAdmin, ur);

                GroupRecord gr = new GroupRecord("ADMIN", newAdmin);
                gr.members.add(newAdmin);
                groupData.put("ADMIN", gr);

                return;
            }
        }
        catch (java.io.IOException e) {
            System.err.println(e);
            return;
        }

        Scanner scanner = null;
        String[] tokens;
        Set<String> groups;
        UserRecord tempRecord; //this is for the loop to add to the list of groups

        try{
             scanner = new Scanner(f);
             while(scanner.hasNextLine()) {

                 // split the line on commas:
                 tokens = scanner.nextLine().split(",");

                 // 1st string is the user, the 2nd is the pass:
                 tempRecord = new UserRecord(tokens[0], tokens[1]);

                 // allocate space for a new set:
                 groups = new HashSet<String>();

                 // add each group to a set:
                 for(int i = 2; i < tokens.length; i++) {
                     groups.add(tokens[i]);
                 }
                 tempRecord.groups = groups;

                 // add the record to our database:
                 userData.put(tokens[0], tempRecord);
             }

        }
        catch (FileNotFoundException e) {System.err.println(e);}
        finally {
            scanner.close();
        }
    }

    private void loadFileData(String fileName) {
        // if the file does not exist,
        // create it.
        File f = new File(fileName);
        try {
            if (f.createNewFile()) {
                return;
            }
        } catch(Exception e) {
            e.printStackTrace();
            return;
        }

        Scanner inscan = null;
        try {
            inscan = new Scanner(f);
            String tmp = null;
            String[] fileVals = null;
            HexString hex = new HexString();
            FileRecord tmpRecord = null;
            while(inscan.hasNextLine()) {
                tmp = inscan.nextLine();
                fileVals = tmp.split("[,]");
                tmpRecord = new FileRecord(fileVals[0], fileVals[1], hex.toByteArray(fileVals[2]));
                fileData.put(fileVals[0], tmpRecord);
            }
        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    // convenience method.
    final void save() {
        saveGroupData(".groupdata/.groups");
        saveUserData(".groupdata/.users");
        saveFileData(".groupdata/.files");
    }

    // saves the group data to a flat file:
    final void saveGroupData(String fileName) {
        
        File f = new File(fileName);
        BufferedWriter bw;

        try{
             bw = new BufferedWriter(new FileWriter(f));

             // write each record to the file:
             for(GroupRecord g : groupData.values()) {
                 bw.write(g.toString());
                 bw.newLine();
             }
             bw.close();
        }
        catch (Exception e) {
            System.err.println(e);
        }

    }

    // saves the user data to a flat file:
    final void saveUserData(String fileName) {

        File f = new File(fileName);
        BufferedWriter bw;

        try{
             bw = new BufferedWriter(new FileWriter(f));

             // write each record to the file:
             for(UserRecord u : userData.values()) {
                 bw.write(u.toString());
                 bw.newLine();
             }
             bw.close();
        }
        catch (Exception e) {
            System.err.println(e);
        }

    }

    private void saveFileData(String fileName) {
        File f = new File(fileName);
        BufferedWriter bw;

        try{
                bw = new BufferedWriter(new FileWriter(f));
                // write each record to the file:
                for (FileRecord u : fileData.values()) {
                    bw.write(u.toString());
                    bw.newLine();
                }
                bw.close();
            }
        catch (Exception e) {
            System.err.println(e);
        }
    }

    // small class to hold user information
    private class UserRecord {
        String name;
        String password;
	Set<String> groups;

        public UserRecord(String name, String pass) {
            this.name = name;
            this.password = pass;
            groups = new HashSet<String>();
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder(name);
            sb.append(',').append(password);
            for(String s : groups)
                sb.append(',').append(s);
            return sb.toString();
        }
    }

    // small class to hold group information
    private class GroupRecord {
        String name;
        String owner; // UserRecord owner?
        Set<String> members;

        private GroupRecord(String groupName, String ownerName) {
            name = groupName;
            owner = ownerName;
            members = new HashSet<String>();
        }

        @Override
        public String toString()
        {
            StringBuilder sb = new StringBuilder(name);
            sb.append(',').append(owner);
            for(String s : members)
                sb.append(',').append(s);
            return sb.toString();
        }
    }

    // TODO: what type do we want to make the file key?
    private class FileRecord {
        String fileName;
        String groupName;
        byte[] fileKey;

        private FileRecord(String fname, String gname, byte[] key) {
            fileName = fname;
            groupName = gname;
            fileKey = key;
        }

        @Override
        public String toString() {
            HexString hex = new HexString();
            return fileName + "," + groupName + "," + hex.toHexString(fileKey);
        }
    }
}
