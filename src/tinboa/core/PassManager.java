package tinboa.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Random;

/**
 *
 * @author gep19
 */
public class PassManager
{

    /* This will create a random password for the user and return it
     * This should be used in new user creation
     */
    public static final char[] createPass() {
        char[] chars = new char[7];
        Random r = new Random();
        for (int i = 0; i < 7; i++) {
            chars[i] = (char) ('0' + r.nextInt(75));
        }
        return chars;
    }

    /**
     * Fills up a character array with a random
     * characters for use as a random password.
     * @param chars
     * @return
     */
    public static final char[] createPass(char[] chars) {
        if (chars.length < 6) {
            return createPass();
        }

        Random r = new Random();
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) ('0' + r.nextInt(75));
        }
        return chars;
    }

    //This will change the password (passwd)
    public static final String changePass(String pass) {

        char invalidChar;
        //Scanner inscan = new Scanner(System.in);

        System.out.print("old password: ");
        //String str = inscan.next();
        String str = readPassword();
        
        if (!pass.equals(new String(str))) {
            System.out.println("incorrect password.");
            return null;
        } else {
            System.out.println("The new password must have at least:");
            System.out.print("1 uppercase letter, 1 lowercase letter ");
            System.out.print("1 symbol/punctuation, ");
            System.out.print("1 digit ");
            System.out.println("and must be at least 8 characters long");
            System.out.print("\010new password: ");
            str = readPassword();
            invalidChar = checkValidChars(str.toCharArray());

            if (invalidChar != '\0') {
                System.out.println("invalid char " + invalidChar + " in the new password");
                return null;
            }

            System.out.print("\010re-type new password: ");

            if(!checkPassStrength(str.toCharArray())){
                System.out.println("Invalid password.");
                System.out.println("The password must contain:");
                System.out.print("1 uppercase letter, 1 lowercase letter ");
                System.out.print("1 symbol/punctuation, ");
                System.out.print("1 digit ");
                System.out.println("and must be at least 8 characters long");

                return null;
            }
            if(!str.equals(readPassword())) {
                System.out.println("the two passwords were not the same.");
                return null;
            }

            return str;
        }
    }

    //This is checks for invalid password char's
    private static char checkValidChars(char[] c) {

        for (int i = 0; i < c.length; i++) {
            if (c[i] < 32 || c[i] > 126) {
                return c[i];
            } else if (c[i] == ',') {
                return c[i];
            }
        }
        return '\0';
    }

    public static String readPassword() {
        MaskingThread mask = new MaskingThread();
        mask.start();

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String password = null;

        try {
            password = in.readLine();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
        // stop masking
        mask.stopMasking();
        // return the password entered by the user
        return password;
    }

    public static boolean checkPassStrength(char[] pass) {
        int lowerCase = 0;
        int upperCase = 0;
        int other = 0;
        int numbers = 0;

        if(pass.length < 8) { return false; }

        for(char c : pass){
            if(Character.isDigit(c)){
                numbers++;
            } else if(Character.isUpperCase(c)){
                upperCase++;
            } else if(Character.isLowerCase(c)){
                lowerCase++;
            } else {
                other++;
            }
        }
        
        return ((lowerCase * upperCase * other * numbers) > 0);
    }
}

class MaskingThread extends Thread
{

    private volatile boolean stop;

    /**
     * Begin masking until asked to stop.
     */
    @Override
    public void run() {

        int priority = Thread.currentThread().getPriority();
        Thread.currentThread().setPriority(Thread.MAX_PRIORITY);

        try {
            stop = true;
            while (stop) {
                System.out.print("\010 ");
                try {
                    // attempt masking at this rate
                    Thread.sleep(1);
                } catch (InterruptedException iex) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        } finally { // restore the original priority
            Thread.currentThread().setPriority(priority);
        }
    }

    /**
     * Instruct the thread to stop masking.
     */
    public void stopMasking() {
        this.stop = false;
    }
}
