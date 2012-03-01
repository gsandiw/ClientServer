
package tinboa.fileserver;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import tinboa.core.FileMessage;

/**
 *
 * @author Yann Le Gall
 * @author Tony Blatt
 * ylegall@gmail.com
 * @date Feb 4, 2010
 */
public class FileManager {
    
    private Set<FileRecord> fileData;
    private static final FileManager instance;
    
    static {
        instance = new FileManager();
    }
            
    private FileManager() {
        fileData = new HashSet<FileRecord>();
        load();
    }
    
    public static final FileManager getInstance() {
        return instance;
    }

    final void listFiles(FileMessage message) {
        List<String> groups = message.token.getGroups();
        StringBuilder sb = new StringBuilder();
        
        for(FileRecord fr : fileData) {
            if(groups.contains(fr.group)) {
                sb.append(fr.file).append(',');
            }
        }

//        for(String group : groups) {
//            sb.append(group).append(":\n");
//            for(FileRecord fr : fileData) {
//                if(groups.contains(fr.group)) {
//                    sb.append('\t').append(fr.file).append(',');
//                }
//            }
//        }
        
        message.message = sb.toString();
        message.success = true;
    }

    final void uploadFile(FileMessage message) {
        String[] tokens = message.message.split(",");
        if(message.token.getGroups().contains(tokens[1])) {
            fileData.add(new FileRecord(tokens[0], tokens[1]));
            message.message = tokens[0];
            message.success = true;
        } else {
            message.message = "unknown group.";
            message.success = false;
        }
    }

    final void downloadFile(FileMessage message) {
        String filename = message.message;
        for(FileRecord r : fileData) {
            if(r.file.equals(filename)) {
                if(message.token.getGroups().contains(r.group)) {
                    message.success = true;
                    return;
                }
            }
        }
        message.message = "file not found.";
        message.success = false;
    }

    final void deleteFile(FileMessage message) {
        String filename = message.message;
        FileRecord record = null;
        for(FileRecord fr : fileData) {
            if(filename.equals(fr.file)) {
                if(message.token.getGroups().contains(fr.group)) {
                    File f = new File(".filedata/"+filename);
                    f.delete();
                    record = fr;
                    message.message += " deleted.";
                    message.success = true;
                } else {
                    message.message = "no such file in your groups.";
                    message.success = false;
                    return;
                }
            }
        }
        fileData.remove(record);
    }

    // this method looks for the .files file
    // in the .filedata directory
    private final void load() {
        try {
            File f = new File(".filedata/");
            if(!f.exists() || !f.isDirectory()) {
                f.mkdir();
            }

            f = new File(".filedata/.files");
            if(!f.exists() || !f.isFile()) {
                f.createNewFile();
            }

            Scanner s = new Scanner(f);
            String[] tokens;
            while(s.hasNextLine()) {
                tokens = s.nextLine().split(",");
                fileData.add(new FileRecord(tokens[0], tokens[1]));
            }
        }
        catch (Exception e) {
            System.err.println(e);
        }
    }

    // this method writes each file,group pair
    // to the .files file in the .filedata directory
    final void save() {
        File f = new File(".filedata/.files");
        BufferedWriter bw;

        try{
             bw = new BufferedWriter(new FileWriter(f));
             for(FileRecord g : fileData) {
                 bw.write(g.toString());
                 bw.newLine();
             }
             bw.close();
        }
        catch (Exception e) {
            System.err.println(e);
        }
    }

    // this private inner class is used to
    // store file,group pairs
    private final class FileRecord {
        private String file;
        private String group;

        public FileRecord(String file, String group) {
            this.file = file;
            this.group = group;
        }

        @Override
        public boolean equals(Object obj) {
            if(obj == null) return false;
            if(obj == this) return true;
            if(obj.getClass().equals(this.getClass())) {
                FileRecord other = (FileRecord)obj;
                return other.file.equals(this.file) && other.group.equals(this.group);
            }
            return false;
        }

        @Override
        public int hashCode() {
            int result = 29 + ((file == null) ? 0 : file.hashCode());
            return 29 * result + ((group == null) ? 0 : group.hashCode());
        }

        @Override
        public String toString() {
            return new StringBuilder(file).append(',').append(group).toString();
        }
    }

}
