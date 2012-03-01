package tinboa.fileserver;

import java.io.File;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * @author Tony Blatt
 * @author Yann Le Gall
 *
 */
public class FileServer {

    public static int SERVER_PORT;
    private static String HOSTNAME;
    private ServerSocket serverSocket;
    private ExecutorService threadPool;
    private boolean isRunning, shutDown;
    File database;

    private FileServer() {
        this(4321);
    }

    private FileServer(int port) {
        try
        {
            threadPool = Executors.newCachedThreadPool();
            isRunning = true;
            shutDown = false;
            SERVER_PORT = port;
            HOSTNAME = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException ex) {
            System.err.println(ex);
        }
    }

    private void launch() {
        Socket socket = null;
        Runtime.getRuntime().addShutdownHook(new ShutdownManager());

        // this line will cause the FileManager class to load automatically
        FileManager.getInstance();
        fSecurityManager.getInstance();

        try {
            // Setup our socket:
            serverSocket = new ServerSocket(SERVER_PORT);
            System.out.println("LINK FileServer listening on port " + SERVER_PORT);

            while (isRunning) {
                // Accept connection:
                socket = serverSocket.accept();
                threadPool.submit(new FileServerJob(socket));
            }

        } catch (Exception e) {
            //System.err.println("Error: " + e.getMessage());
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
        if (shutDown) {
            return;
        }
        System.out.println("file server shutting down.");
        try {
            threadPool.shutdown();
            if (!serverSocket.isClosed()) {
                serverSocket.close();
            }
            FileManager.getInstance().save();
            shutDown = true;
            //System.out.println("here!");
        } catch (Exception e) {
            System.err.println(e);
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
        // more than 0 args
        if (args.length > 0) {
            try {
                int port = Integer.parseInt(args[0]);
                if (port < 1024) {
                    System.out.println("Invalid port:" + args[0]);
                    new FileServer().launch();
                } else {
                    new FileServer(port).launch();
                }
            } catch (NumberFormatException e) {
                System.out.println("invalid port: " + args[0]);
                new FileServer().launch();
            }
        } else {
            // 0 args
            new FileServer().launch();
        }
    }
}
