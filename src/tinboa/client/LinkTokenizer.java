package tinboa.client;

/**
 *  @author Yann Le Gall
 *  ylegall@gmail.com
 *  Feb 9, 2010 3:37:17 PM
 */
public class LinkTokenizer {

    /**
     * Splits a string into an array of tokens. Treats substrings enclosed
     * in quotes as a single token. The * character is not allowed. This
     * method does not account for strings containing unclosed quotations.
     * @param s the string to be tokenized
     * @param delim the delimiter
     * @return an array of tokens
     */
    public final String[] split(String s, char delim) {
        boolean inQuotes = false;
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (inQuotes) {
                if (c == '"') {
                    inQuotes = false;
                } else {
                    sb.append(c);
                }
            } else {
                if (c == '"') {
                    inQuotes = true;
                } else if (c == delim) {
                    sb.append('*');
                } else {
                    sb.append(c);
                }
            }
        }
        return sb.toString().split("\\*+");
    }
}
