package tinboa.server;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * A Group Server class.
 *
 * @author Yann G. Le Gall
 * ylegall@gmail.com
 *
 */
public final class GroupServer {

    private static String HOSTNAME;
    private ServerSocket serverSocket;
    private ExecutorService threadPool;
    private boolean isRunning, shutDown;

    private GroupServer() {
        this(8765);
    }

    private GroupServer(int port) {
        try {
            threadPool = Executors.newCachedThreadPool();
            isRunning = true;
            shutDown = false;
            HOSTNAME = InetAddress.getLocalHost().getHostName();
            launch(port);
        } catch (UnknownHostException ex) {
            System.err.println(ex);
        }
    }

    private void launch(int port) {
        Socket socket = null;
        Runtime.getRuntime().addShutdownHook(new ShutdownManager());

        // these lines invoke the static class loader
        Database.getInstance();
        SecurityManager.getInstance();

        try {
            // Setup our socket:
            serverSocket = new ServerSocket(port);
            System.out.println("LINK GroupServer listening on port " + port);

            while (isRunning) {
                // Accept connection:
                socket = serverSocket.accept();
                threadPool.submit(new ServerJob(socket));
            }

        } catch (Exception e) {
            //System.err.println("Error main-loop: " + e.getMessage());
            //e.printStackTrace(System.err);
        } finally {
            //System.out.println("*** DEBUG: in the finally block");
        }

        // clean-up resources here:
        shutdown();
    }
    
    // this method takes care of disposing resources
    // and saving any state. The database.save()
    // method should be invoked here.
    private synchronized void shutdown() {
        if (shutDown) { return; }
        System.out.println("server shutting down.");
        try {
            threadPool.shutdown();
            if (!serverSocket.isClosed()) {
                serverSocket.close();
            }
            Database.getInstance().save();
            shutDown = true;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    final static String getHostName() {
        return HOSTNAME;
    }

    // this thread is run by the JVM just before program
    // termination. It is responsible for cleaning up
    // resources and shutting down gracefully.
    private final class ShutdownManager extends Thread {

        @Override
        public void run() {
            System.out.println("*** DEBUG: ctrl-c caught");
            shutdown();
        }
    }

    /**
     * Program entry point.
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // more than 0 args: try to parse 1st as a port
        if (args.length > 0) {
            try {
                int port = Integer.parseInt(args[0]);
                if (port < 1024) {
                    System.out.println("Invalid port:" + port);
                    new GroupServer();
                } else {
                    new GroupServer(port);
                }
            } catch (NumberFormatException e) {
                System.out.println("invalid port: " + args[0]);
                new GroupServer();
            }
        } else {
            // 0 args: use default port
            new GroupServer();
        }
    }
}
