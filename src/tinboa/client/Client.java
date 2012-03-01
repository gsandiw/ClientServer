package tinboa.client;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import tinboa.core.HexString;
import tinboa.core.PassManager;
import tinboa.core.UserToken;
import static java.lang.System.out;

/**
 *  @author Yann Le Gall
 *  ylegall@gmail.com
 *  Jan 27, 2010 11:29:10 AM
 */
public class Client
{

    private UserToken token;
    private FileClient fileClient;
    private GroupClient groupClient;
    private boolean isRunning;
    private Map<String, Invokable> commandMap;
    private String username, hostname;
    private String pass;

    private Client() {
        groupClient = new GroupClient();
        fileClient = new FileClient();
        commandMap = new Hashtable<String, Invokable>();
        initCommands();
        SecurityManager.getInstance();
        isRunning = true;
    }

    private void launch() {

        printBanner();
        Scanner scanner = new Scanner(System.in);
        LinkTokenizer lt = new LinkTokenizer();

        try {
            while (isRunning) {
                out.print("\n ");
                if (username != null) {
                    out.print(username);
                }
                if (hostname != null) {
                    out.print("@" + hostname);
                }
                out.print(" >>> ");

                if (scanner.hasNextLine()) {
                    String line = scanner.nextLine().trim();
                    processArgs(lt.split(line, ' '));
                    //processArgs(line.split("\\s+"));
                } else {
                    break; // EOF
                }
            }
        } catch (Exception e) {
            System.err.println(e);
            e.printStackTrace();
        }

        scanner.close();
        shutdown();
    }

    private final void processArgs(String[] args) {
        boolean success = false;
        if (args[0].length() < 1) {
            return;
        }

        Invokable method = commandMap.get(args[0]);
        if (method == null) {
            out.println("\nunknown command: " + args[0]);
        } else {
            success = method.invoke(args);
            if (!success) {
                out.println("operation failed.");
            }
        }
    }

    private static final void printBanner() {

        out.println("    __  _       _    ");
        out.println("   / / (_)_ __ | | __");
        out.println("  / /  | | '_ \\| |/ /");
        out.println(" / /___| | | | |   < ");
        out.println(" \\____/|_|_| |_|_|\\_\\");

        out.println("\n============ Link Is Not Kerberos ============");
        out.println("welcom to the LINK file-sharing system, v1.0.0");
        out.println("type 'help' for a list of commands.");
        out.println("type 'exit' to quit.");
    }

    /**
     * prints a list of commands.
     */
    static final void printHelp() {

        out.println("\n login HOSTNAME PORT  connects to the server at 'hostname'");
        out.println(" logout                 disconnects from the groupserver.");
        out.println(" useradd USER           creates a user.");
        out.println(" userdel USER           removes a user.");
        out.println(" su USER                switches the current user.");
        out.println(" passwd                 changes your password.");
        out.println(" newkey GROUP           makes a new group file key");
        out.println(" lsgroup                lists your groups.");
        out.println(" groupadd GROUP         creates a group.");
        out.println(" groupdel GROUP         removes a group.");
        out.println(" memadd USER GROUP      adds a user to a group.");
        out.println(" memdel USER GROUP      removes a user from a group.");
        out.println(" lsmem GROUP            lists members of a group.");
        out.println(" flogin HOSTNAME PORT   connects to a fileserver.");
        out.println(" flogout                disconnects from a fileserver.");
        out.println(" upload SRC DST GRP     upload file SRC as DST in group GRP.");
        out.println(" download SRC DST       downloads file SRC as DST.");
        out.println(" rm FILE                deletes FILE from the fileserver.");
        out.println(" ls                     lists your files.");
        out.println(" help                   displays this list of commands.");
        out.println(" exit                   exit the system.");
    }

    // causes the client program to exit.
    private final void exit() {
        isRunning = false;
    }

    /**
     * dispose any resources and shutdown gracefully
     */
    private final void shutdown() {
        try {
            fileClient.disconnect();
            groupClient.disconnect();
            SecurityManager sm = SecurityManager.getInstance();
            sm.saveServerKey();
            sm.saveFileServerKey();
        } catch (Exception e) {
            System.err.println(e);
        }
        out.println("\nGood-bye.\n");
    }

    // This method populates a hashtable with
    // a set of anonymous Invokable objects.
    // each invokable is triggered by a corresponding
    // string command.
    private final void initCommands() {

        commandMap.put("help", new Invokable()
        {

            public boolean invoke(String[] args) {
                printHelp();
                return true;
            }
        });

        commandMap.put("exit", new Invokable()
        {

            public boolean invoke(String[] args) {
                exit();
                return true;
            }
        });

        commandMap.put("login", new Invokable()
        {

            public boolean invoke(String[] args) {
                if (args.length < 3) {
                    out.println("not enough arguments.");
                    out.println("usage: login <HOSTNAME> <PORT>.");
                    return false;
                } else {
                    String pw;
                    try {

                        // try to open a connection with the host:
                        if (!groupClient.connect(args[1], Integer.parseInt(args[2]))) {
                            System.err.println("Invalid hostname/port: " + args[1]);
                            return false;
                        } else {

                            // request and check public RSA key/
                            // if it is not recognized, ask the user if
                            // they accept it.
                            if (!groupClient.getPublicKey(args[1])) {

                                out.println("key rejected.");
                                groupClient.disconnect();
                                return false;
                            }

                            // prompt for username and pass:
                            Scanner scanner = new Scanner(System.in);
                            out.print("username: ");
                            String user = scanner.nextLine();

                            out.print("password: ");

                            // immediately hash password:
                            HexString hex = new HexString();
                            pw = hex.toHexString(SecurityManager.digest(PassManager.readPassword().getBytes()));

                            // get a token from the group server:
                            token = groupClient.getToken(user, pw);

                            if (token == null) {
                                groupClient.disconnect();
                                pass = username = null;
                                return false;
                            }
                        }
                    } catch (NumberFormatException e) {
                        out.println("invalid port: " + args[2]);
                        return false;
                    }
                    out.println("\010logged in.");
                    username = token.getSubject();
                    pass = pw;
                    return true;
                }
            }
        });

        commandMap.put("newkey", new Invokable()
        {
            public boolean invoke(String[] args) {
                List<String> groups;
                
                if(args[1] == null){
                    out.println("too few arguments");
                    out.println("usage: newkey GROUP");
                    return false;
                }

                //verify that the user owns the group
                groups = groupClient.listMembers(args[1], token);
                if(groups == null){
                    out.println("only the owner may change the key");
                }

                groupClient.backUpKey(); //Back up the session key
                //Make a new session key by contacting Group Server
                //Let the user worry about downloading from the files.
                return true;
            }
        });

        commandMap.put("su", new Invokable()
        {

            public boolean invoke(String[] args) {

                if (token == null) {
                    out.println("not connected to the group-server.");
                    return false;
                }
                String user = null;
                String pw = null;
                Scanner scanner = new Scanner(System.in);
                switch (args.length) {
                    case 1:
                        out.print("username: ");
                        user = scanner.nextLine();
                        out.print("password: ");
                        pw = PassManager.readPassword();

                        break;
                    case 2:
                        user = args[1];
                        out.print("password: ");
                        pw = PassManager.readPassword();

                        break;
                    default:
                        out.println("too many arguments.");
                        out.println("usage: su [USER]");
                }

                UserToken t = groupClient.getToken(user, pw, hostname);
                if (t == null) {
                    //groupClient.disconnect();
                    return false;
                } else {
                    token = t;
                    out.println("logged in.");
                    username = token.getSubject();
                    pass = pw;
                    return true;
                }
            }
        });

        commandMap.put("flogin", new Invokable()
        {
            public boolean invoke(String[] args) {

                // first check the syntax of the command:
                if (args.length < 3) {
                    out.println("not enough arguments.");
                    out.println("usage: flogin <HOSTNAME> <PORT>.");
                    return false;
                }

                try {
                    
                    // try to connect to the specified file server:
                    if (!fileClient.connect(args[1], Integer.parseInt(args[2]))) {
                        System.err.println("Invalid hostname/port: " + args[1]);
                        return false;
                    } else {

                        // request and check public RSA key.
                        // if it is not recognized, ask the user if
                        // they trust it.
                        if (fileClient.getFileKey(args[1])) {

                            // make sure to use the correct
                            // host name if the server and client
                            // are both running on same machine:
                            if (args[1].equals("localhost")) {
                                try {
                                    hostname = InetAddress.getLocalHost().getHostName();
                                } catch (UnknownHostException ex) {
                                    out.println(ex.getMessage());
                                }

                            } else {
                                hostname = args[1];
                            }

                            // make sure that the token is updated:
                            token = groupClient.getToken(username, pass, hostname);
                            return true;

                        } else {

                            // session key was not established
                            out.println("key rejected.");
                            groupClient.disconnect();
                            return false;
                        }
                    }

                } catch (NumberFormatException e) {
                    out.println("invalid port: " + args[2]);
                    return false;
                }
            }
        });

        commandMap.put("logout", new Invokable()
        {
            public boolean invoke(String[] args) {
                commandMap.get("flogout").invoke(null);
                groupClient.disconnect();
                token = null;
                username = pass = null;
                return true;
            }
        });

        commandMap.put("flogout", new Invokable()
        {
            public boolean invoke(String[] args) {
                hostname = null;
                fileClient.disconnect();
                return true;
            }
        });

        commandMap.put("download", new Invokable()
        {

            public boolean invoke(String[] args) {
                if (args.length < 3) {
                    out.println("not enough arguments.");
                    out.println("usage: download <SOURCE> <DEST>.");
                    return false;
                } else if (token == null) {
                    out.println("not logged in.");
                    return false;
                } else if (!fileClient.isConnected()) {
                    out.println("not logged in to a fileServer.");
                    return false;
                } else {
                    // make sure to update the Token
                    token = groupClient.getToken(username, pass.toString(), hostname);
                    String h2 = "";
                    if(!(hostname == null))
                        h2 = hostname;

                    if(fileClient.download(args[1], args[2], token, groupClient, username, h2, pass)){
                        File s = new File(args[1] + ".tmp");
                        File d = new File(args[2] + ".tmp");
                        s.delete();
                        d.delete();
                        return true;
                    } else {
                        throw new IllegalArgumentException("Delete: deletion failed");
                    }
                    
                }
            }
        });

        commandMap.put("upload", new Invokable()
        {

            public boolean invoke(String[] args) {
                if (args.length < 4) {
                    out.println("not enough arguments.");
                    out.println("usage: upload <SOURCE> <DEST> <GROUP>.");
                    return false;
                } else if (token == null) {
                    out.println("not logged in.");
                    return false;
                } else if (!fileClient.isConnected()) {
                    out.println("not logged in to a fileServer.");
                    return false;
                } else {
                    // make sure to update the Token
                    token = groupClient.getToken(username, pass, hostname);
                    //String h2 = "";
                    //if(!(hostname == null))
                        //h2 = hostname;
                    return fileClient.upload(args[1], args[2], args[3], token, groupClient, username, hostname, pass);
                }
            }
        });

        commandMap.put("rm", new Invokable()
        {

            public boolean invoke(String[] args) {
                if (args.length < 2) {
                    out.println("not enough arguments.");
                    out.println("usage: rm <FILE>.");
                    return false;
                } else if (token == null) {
                    out.println("not logged in.");
                    return false;
                } else if (!fileClient.isConnected()) {
                    out.println("not logged in to a fileServer.");
                    return false;
                } else {
                    // make sure to update the Token
                    token = groupClient.getToken(username, pass, hostname);
                    if(fileClient.delete(args[1], token))
                        return groupClient.delete(args[1], token, username, pass, hostname);
                    else
                        return false;
                }
            }
        });

        commandMap.put("ls", new Invokable()
        {

            public boolean invoke(String[] args) {
                if (token == null) {
                    out.println("not logged in.");
                    return false;
                } else if (!fileClient.isConnected()) {
                    out.println("not logged in to a fileServer.");
                    return false;
                } else {
                    // make sure to update the Token
                    token = groupClient.getToken(username, pass, hostname);
                    List<String> list = fileClient.listFiles(token);
                    if (list == null) {
                        return false;
                    } else if (list.size() == 0) {
                        out.println("no files.");
                    } else {

                        // list each file:
                        for (String s : list) {
                            out.println(" " + s);
                        }
                        out.print(list.size());

                        if (list.size() == 1) {
                            out.println(" file.");
                        } else {
                            out.println(" files.");
                        }
                    }
                    return true;
                }
            }
        });

        commandMap.put("groupadd", new Invokable()
        {

            public boolean invoke(String[] args) {
                if (args.length < 2) {
                    out.println("not enough arguments.");
                    out.println("usage: groupadd GROUP.");
                    return false;
                } else if (token == null) {
                    out.println("not logged in.");
                    return false;
                } else if (args[1].contains(",")) {
                    out.println("group name cannot contain comma's");
                    return false;
                } else {
                    // create the group:
                    boolean succeeded = groupClient.createGroup(args[1], token);

                    return succeeded;
                }
            }
        });

        commandMap.put("groupdel", new Invokable()
        {

            public boolean invoke(String[] args) {
                if (args.length < 2) {
                    out.println("not enough arguments.");
                    out.println("usage: groupdel GROUP.");
                    return false;
                } else if (token == null) {
                    out.println("not logged in.");
                    return false;
                } else {
                    if (groupClient.deleteGroup(args[1], token)) {
                        token.getGroups().remove(args[1]);
                        return true;
                    }
                    return false;
                }
            }
        });

        commandMap.put("useradd", new Invokable()
        {

            public boolean invoke(String[] args) {
                if (args.length < 2) {
                    out.println("not enough arguments.");
                    out.println("usage: useradd USER.");
                    return false;
                } else if (token == null) {
                    out.println("not logged in.");
                    return false;
                } else if (args[1].contains(",")) {
                    out.println("usernames cannot contain comma's");
                    return false;
                } else {
                    return groupClient.createUser(args[1], token);
                }
            }
        });

        commandMap.put("userdel", new Invokable()
        {

            public boolean invoke(String[] args) {
                if (args.length < 2) {
                    out.println("not enough arguments.");
                    out.println("usage: userdel USER.");
                    return false;
                } else if (token == null) {
                    out.println("not logged in.");
                    return false;
                } else {
                    return groupClient.deleteUser(args[1], token);
                }
            }
        });

        commandMap.put("memadd", new Invokable()
        {

            public boolean invoke(String[] args) {
                if (args.length < 3) {
                    out.println("not enough arguments.");
                    out.println("usage: addmem USER GROUP.");
                    return false;
                } else if (token == null) {
                    out.println("not logged in.");
                    return false;
                } else {
                    return groupClient.addUserToGroup(args[1], args[2], token);
                }
            }
        });

        commandMap.put("memdel", new Invokable()
        {

            public boolean invoke(String[] args) {
                if (args.length < 3) {
                    out.println("not enough arguments.");
                    out.println("usage: delmem USER GROUP.");
                    return false;
                } else if (token == null) {
                    out.println("not logged in.");
                    return false;
                } else {
                    return groupClient.deleteUserFromGroup(args[1], args[2], token);
                }
            }
        });

        commandMap.put("lsmem", new Invokable()
        {

            public boolean invoke(String[] args) {
                if (args.length < 2) {
                    out.println("not enough arguments.");
                    out.println("usage: lsmem GROUP.");
                    return false;
                } else if (token == null) {
                    out.println("not logged in.");
                    return false;
                } else {
                    List<String> list = groupClient.listMembers(args[1], token);
                    if (list == null) {
                        return false;
                    } else {
                        out.println();

                        // list each member:
                        for (String member : list) {
                            out.println(" " + member);
                        }
                        out.println("members: " + list.size());
                        return true;
                    }
                }
            }
        });

        commandMap.put("lsgroup", new Invokable()
        {

            public boolean invoke(String[] args) {
                if (token == null) {
                    out.println("not logged in.");
                    return false;
                } else {
                    List<String> list = groupClient.listGroups(token);
                    if (list == null) {
                        return false;
                    }

                    int size = list.size();
                    if (size > 0) {
                        out.println();

                        // list each group:
                        for (String s : list) {
                            out.println(" " + s);
                        }
                        out.print(size);

                        if (size > 1) {
                            out.println(" groups.");
                        } else {
                            out.println(" group.");
                        }
                    } else {
                        out.println("not a member of any groups.");
                    }
                    return true;
                }
            }
        });

        commandMap.put("passwd", new Invokable()
        {

            public boolean invoke(String[] args) {
                if (token == null) {
                    out.println("not logged in.");
                    return false;
                } else {
                    String newPass;
                    newPass = PassManager.changePass(pass);
                    if (newPass != null) {
                        return groupClient.changePass(pass, newPass, token);
                    } else {
                        return false;
                    }
                }
            }
        });
    }

    /**
     * this interface is used to associate
     * client methods with a command.
     */
    private interface Invokable
    {

        public boolean invoke(String[] args);
    }

    /**
     * Program entry point.
     * @param args the command line arguments.
     */
    public static void main(String[] args) {
        new Client().launch();
    }
}
