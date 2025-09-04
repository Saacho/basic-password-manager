import java.io.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.nio.*;
import java.text.*;
public class PasswordVault {
    private HashMap < String, String > vault; // stores username-password pairs
    private LinkedList < String > passwordList; // list of passwords (for display)
    private Stack < String > actionHistory; // stack to keep track of actions
    private String adminPassword; // admin password for verification
    private final String adminPasswordFile = "admin_password.txt"; // admin password file
    private final String userPasswords = "user_passwords.csv"; // user passwords file
    private final String logFile = "vault_log.txt"; // action logs file
    private final String saltFile = "salt.txt"; // salt file
    private String salt = "salty";
    private final String keyFile = "key.dat"; // key file
    private static final int iterations = 600000;
    private static final int keyLength = 128;
    private SecretKeySpec secretKeySpec;
    private LinkedList < String > wordList = new LinkedList < > ();
    private final String vowels = "AEIOUaeiou";
    private final String uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private final String lowercase = "abcdefghijklmnopqrstuvwxyz";
    private final String numbers = "0123456789";
    private final String symbols = "~!@#$%^&*()_+{}|:>\"<?`-=[]\\;',./";
    private static String characters =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~!@#$%^&*()_+{}|:>\"<?`-=[]\\;',./";
    private static Scanner reader = new Scanner(System.in);
    public PasswordVault() {
        vault = new HashMap < > ();
        passwordList = new LinkedList < > ();
        actionHistory = new Stack < > ();
        loadSalt();
        loadKey();
        if (secretKeySpec == null) {
            System.out.println("Unable to load existing encryption data.");
            System.out.println("You will lose any previously stored passwords should you choose to generate a new key and salt.");
                System.out.print("Export passwords before reinitializing encryption? (Y/N): ");
                if (reader.nextLine().equalsIgnoreCase("Y")) {
                    System.out.println("Please enter the file path below:");
                    String filePath = reader.nextLine();
                    export (filePath);
                }
                System.out.print("Continue with a new encryption setup? (Y/N): ");
                if (!reader.nextLine().equalsIgnoreCase("Y")) {
                    System.out.println("Setup aborted. Restore encryption data to access passwords.");
                    System.exit(0);
                }
                System.out.print("Enter encryption input: "); String masterPassword = reader.nextLine(); generateKey(masterPassword); saveKey();
            }
            loadAdminPassword();
            BufferedReader br = null;
            try {
                br = new BufferedReader(new FileReader(userPasswords));
                loadPasswordsFromCSV();
            } catch (FileNotFoundException e) {
                System.out.println("No password CSV file found (skipping load)."); // checks if there is a CSV file and if not, skips loading
            } catch (Exception e) {
                System.out.println("An error occurred while trying to read the CSV file.");
            } finally {
                if (br != null) {
                    try {
                        br.close();
                    } catch (IOException e) {
                        System.out.println("Failure to close resources.");
                    }
                }
            }
        }
        private void generateKey(String password) {
            try {
                PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, keyLength); // provides settings to SKF
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // applies hash function given spec settings
                byte[] keyBytes = keyFactory.generateSecret(spec).getEncoded(); // puts it in a byte[] using getEncoded() which extracts the bytes
                secretKeySpec = new SecretKeySpec(keyBytes, "AES"); // wraps raw key so encrypt. algorithm can read it and assigns it to secretKeySpec
                logAction("AES key generated.");
            } catch (Exception e) {
                System.out.println("Error generating key: " + e.getMessage());
            }
        }
        private void saveKey() {
            PrintWriter pw = null;
            try {
                pw = new PrintWriter(keyFile);
                String encodedKey = Base64.getEncoder().encodeToString(secretKeySpec.getEncoded()); // convert to chars
                pw.println(encodedKey); // writes to file
            } catch (IOException e) {
                System.out.println("Error saving key: " + e.getMessage());
            } finally {
                if (pw != null) {
                    try {
                        pw.close();
                    } catch (Exception e) {
                        System.out.println("Failure to close resources.");
                    }
                }
            }
        }
        private boolean loadKey() {
            BufferedReader br = null;
            try {
                br = new BufferedReader(new FileReader(keyFile));
                String encodedKey = br.readLine();
                if (encodedKey == null || encodedKey.isEmpty()) {
                    System.out.println("key.dat is empty.");
                    return false;
                }
                byte[] keyBytes = Base64.getDecoder().decode(encodedKey); // converts back to bytes
                secretKeySpec = new SecretKeySpec(keyBytes, "AES"); // same as in generateKey() (kind of redundant but I didn 't want to risk unreadable key somewhere)
                return true;
            } catch (IOException e) {
                System.out.println("No existing key found.");
                return false;
            } finally {
                if (br != null) {
                    try {
                        br.close();
                    } catch (IOException e) {
                        System.out.println("Failure to close resources.");
                    }
                }
            }
        }
        private void generateSalt() {
            byte[] saltBytes = new byte[16]; // 128 bits = 16 bytes
            new SecureRandom().nextBytes(saltBytes);
            salt = Base64.getEncoder().encodeToString(saltBytes); // convert to chars
        }
        private void saveSalt() {
            PrintWriter pw = null;
            try {
                pw = new PrintWriter(saltFile);
                pw.println(salt);
            } catch (IOException e) {
                System.out.println("Error saving salt.");
            } finally {
                if (pw != null) {
                    try {
                        pw.close();
                    } catch (Exception e) {
                        System.out.println("Failure to close resources.");
                    }
                }
            }
        }
        private boolean loadSalt() {
            BufferedReader br = null;
            try {
                br = new BufferedReader(new FileReader(saltFile));
                salt = br.readLine();
                if (salt == null || salt.isEmpty()) {
                    System.out.println("Salt data is invalid. Generating new salt.");
                    generateSalt();
                    saveSalt();
                    return false;
                }
                return true;
            } catch (IOException e) {
                System.out.println("No existing salt found. Generating new salt.");
                generateSalt();
                saveSalt();
                return false;
            } finally {
                if (br != null) {
                    try {
                        br.close();
                    } catch (IOException e) {
                        System.out.println("Failure to close resources.");
                    }
                }
            }
        }
        private void loadAdminPassword() {
            BufferedReader br = null;
            try {
                br = new BufferedReader(new FileReader(adminPasswordFile));
                adminPassword = br.readLine();
                if (adminPassword == null || adminPassword.trim().isEmpty()) {
                    adminPassword = "admin";
                    saveAdminPassword();
                }
            } catch (IOException e) {
                adminPassword = "admin";
                saveAdminPassword();
            } finally {
                if (br != null) {
                    try {
                        br.close();
                    } catch (IOException e) {
                        System.out.println("Failure to close resources.");
                    }
                }
            }
        }
        public String getSalt() {
            return salt;
        }
        public byte[] getAESKey() {
            if (secretKeySpec != null) {
                return secretKeySpec.getEncoded();
            }
            return null;
        }
        private void saveAdminPassword() {
            PrintWriter pw = null;
            try {
                pw = new PrintWriter(adminPasswordFile);
                pw.println(adminPassword);
            } catch (IOException e) {
                System.out.println("Error saving admin password.");
            } finally {
                if (pw != null) {
                    try {
                        pw.close();
                    } catch (Exception e) {
                        System.out.println("Failure to close resources.");
                    }
                }
            }
        }
        public String getAdminPassword() {
            return adminPassword;
        }
        private void loadPasswordsFromCSV() {
            if (secretKeySpec == null) {
                System.out.println("There is no valid key available (cannot decrypt any existing passwords).");
                return;
            }
            BufferedReader br = null;
            try {
                br = new BufferedReader(new FileReader(userPasswords));
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.startsWith("\"")) { // handles entries with commas
                        int endQuoteIndex = line.indexOf("\",\"");
                        if (endQuoteIndex > 0) {
                            String username = line.substring(1, endQuoteIndex);
                            String encryptedPassword = line.substring(endQuoteIndex + 3, line.length() - 1);
                            String password = decrypt(encryptedPassword);
                            if (password != null) {
                                vault.put(username, password);
                                passwordList.add(password);
                            } else {
                                System.out.println("Could not decrypt password for user: " + username);
                            }
                        } else {
                            System.out.println("Skipping bad line.");
                        }
                    } else {
                        System.out.println("Skipping bad line.");
                    }
                }
            } catch (IOException e) {
                System.out.println("Error loading passwords from CSV: " + e.getMessage());
            } finally {
                if (br != null) {
                    try {
                        br.close();
                    } catch (IOException e) {
                        System.out.println("Failure to close resources.");
                    }
                }
            }
        }
        public void
        export (String filePath) {
            BufferedReader br = null;
            BufferedWriter bw = null;
            try {
                File inputFile = new File(userPasswords);
                if (!inputFile.exists() || inputFile.length() == 0) { // check if the input file exists and is not empty
                    System.out.println("No password CSV file found or file is empty (skipping export).");
                    return; // exit method if the file doesn't exist or is empty
                }
                br = new BufferedReader(new FileReader(userPasswords));
                bw = new BufferedWriter(new FileWriter(filePath));
                bw.write("Username\t\t\t\t\t\t\t\tPassword");
                bw.newLine();
                String row;
                while ((row = br.readLine()) != null) { // until run out of rows
                    String[] data = row.split("\",\""); // split each line based on quoted CSV format (b/c of comma issues)
                if (data.length == 2) {
                    String username = data[0].replaceFirst("^\"",
                        "").trim(); // remove starting and ending quotes
                    String encryptedPassword = data[1].replaceFirst("\"$",
                        "").trim();
                    bw.write("\"" + username + "\"\t\t\t\t\t\t\t\t\"" + encryptedPassword + "\""); // write to output file
                    bw.newLine();
                } else {
                    System.out.println("Skipping bad line.");
                }
            }
            System.out.println("Export successful. File saved at: " + filePath);
        } catch (IOException e) {
            System.out.println("An error occurred while exporting: " + e.getMessage());
        } finally {
            try {
                if (br != null) {
                    br.close();
                }
                if (bw != null) {
                    bw.close();
                }
            } catch (IOException e) {
                System.out.println("Failure to close resources.");
            }
        }
    }
    private void savePasswordsToCSV() {
        PrintWriter pw = null;
        try {
            pw = new PrintWriter(userPasswords);
            for (String key: vault.keySet()) {
                String value = vault.get(key);
                if (value != null) {
                    pw.println("\"" + key + "\",\"" + encrypt(value) + "\""); // handles entries with commas by putting them in quotes (native CSV text qualifier)
                } else {
                    System.out.println("Skipping password for user " + key + " (null).");
                }
            }
        } catch (IOException e) {
            System.out.println("Error saving passwords to CSV.");
        } finally {
            if (pw != null) {
                pw.close();
            }
        }
    }
    private String checkPasswordStrength(String password) {
        int length = password.length();
        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasNumber = false;
        boolean hasSpecial = false;
        for (int i = 0; i < length; i++) {
            char c = password.charAt(i);
            if (uppercase.indexOf(c) >= 0) {
                hasUpper = true;
            } else if (lowercase.indexOf(c) >= 0) {
                hasLower = true;
            } else if (numbers.indexOf(c) >= 0) {
                hasNumber = true;
            } else if (symbols.indexOf(c) >= 0) {
                hasSpecial = true;
            }
        }
        if ((length >= 12 && hasUpper && hasLower && hasNumber && hasSpecial) || (length >= 30)) {
            return "Strong";
        } else if (length >= 8 && (hasUpper || hasLower) && hasNumber) {
            return "Moderate";
        } else {
            return "Weak";
        }
    }
    public void addPassword(String username) {
        if (username == null) {
            System.out.println("Username cannot be null.");
            return;
        }
        StringBuilder password = new StringBuilder();
        System.out.println("Enter password character by character to check strength. Type '-' to delete the last
            character.Press Enter when done.
            ");
            System.out.println();
            while (true) {
                System.out.print("\033[1F\033[K"); // clears line so password updates in place
                System.out.print("Password: " + password + " | Strength: " + checkPasswordStrength(password.toString()) +
                    " | Input: ");
                String input = reader.nextLine();
                if (input.equals("-")) {
                    if (password.length() > 0) {
                        password.setLength(password.length() - 1);
                    }
                } else if (input.isEmpty()) {
                    break;
                } else {
                    password.append(input);
                }
            }
            String finalPassword = password.toString(); vault.put(username, finalPassword); passwordList.add(finalPassword); actionHistory.push("ADD," + username + "," + finalPassword); savePasswordsToCSV(); System.out.println("\nPassword added for user: " + username); logAction("Added password for user: " + username);
        }
        public void addTestPassword(String username, String password) {
            vault.put(username, password);
            passwordList.add(password);
            savePasswordsToCSV();
        }
        public void removePassword(String username) {
            if (username == null) {
                System.out.println("Username cannot be null.");
                return;
            }
            if (vault.containsKey(username)) {
                System.out.println("Enter the password for user: " + username);
                String inputPassword = reader.nextLine();
                String actualPassword = vault.get(username);
                if (actualPassword == null) {
                    System.out.println("Password not found for user: " + username);
                    return;
                }
                if (!actualPassword.equals(inputPassword)) {
                    System.out.println("Incorrect password.");
                    return;
                }
                vault.remove(username);
                passwordList.remove(actualPassword);
                actionHistory.push("REMOVE," + username + "," + actualPassword);
                savePasswordsToCSV();
                System.out.println("Password removed for user: " + username);
            } else {
                System.out.println("Password not found for user: " + username);
            }
            logAction("Removed password for user: " + username);
        }
        public String generateRandomPassword() {
            loadWordsFromFile("words_alpha.txt");
            System.out.println("Would you like to generate a (1) password or a (2) passphrase?");
            String choice = reader.nextLine();
            if (choice.equals("1")) {
                return generatePassword();
            } else if (choice.equals("2")) {
                System.out.println("(Y/N) Would you like to use a specific acronym?");
                String choice1 = reader.nextLine();
                if (choice1.equalsIgnoreCase("Y")) {
                    return acronymPassphrase();
                } else {
                    return generatePassphrase();
                }
            } else {
                System.out.println("Invalid choice. Enter (1) for password or (2) for passphrase.");
                return generateRandomPassword();
            }
        }
        private void loadWordsFromFile(String filePath) {
            BufferedReader br = null;
            try {
                br = new BufferedReader(new FileReader(filePath));
                String line;
                while ((line = br.readLine()) != null) {
                    line = line.trim().toLowerCase();
                    if (isValidWord(line)) {
                        wordList.add(line);
                    }
                }
            } catch (IOException e) {
                System.out.println("Error reading word list from file: " + e.getMessage());
            } finally {
                if (br != null) {
                    try {
                        br.close();
                    } catch (IOException e) {
                        System.out.println("Failure to close resources.");
                    }
                }
            }
        }
        private boolean isSingleLetterWord(String word) {
            if (word.length() == 1) {
                return true;
            }
            char firstChar = word.charAt(0);
            for (int i = 1; i < word.length(); i++) {
                if (word.charAt(i) != firstChar) {
                    return false;
                }
            }
            return true;
        }
        private boolean isValidWord(String word) {
            if (word.length() < 4 || word.length() > 6) {
                return false;
            }
            for (int i = 0; i < word.length(); i++) {
                char c = word.charAt(i);
                if (uppercase.indexOf(c) == -1 && lowercase.indexOf(c) == -1) {
                    return false;
                }
            }
            return (containsVowel(word) && !isSingleLetterWord(word));
        }
        private boolean containsVowel(String word) {
            for (int i = 0; i < word.length(); i++) {
                char c = word.charAt(i);
                if (vowels.indexOf(c) != -1) {
                    return true;
                }
            }
            return false;
        }
        private String generatePassphrase() {
            System.out.println("How many words should the passphrase contain?");
            int wordCount = getLength();
            Random random = new Random();
            StringBuilder passphrase = new StringBuilder();
            for (int i = 0; i < wordCount; i++) {
                if (i > 0) {
                    passphrase.append("-");
                }
                passphrase.append(wordList.get(random.nextInt(wordList.size())));
            }
            logAction("Random passphrase generated.");
            return passphrase.toString();
        }
        private String acronymPassphrase() {
            System.out.println("How many words should the passphrase contain?");
            int wordCount = getLength();
            System.out.println("Please enter the acronym.");
            String acronym = reader.nextLine();
            String[] letters = acronym.split("");
            Random random = new Random();
            StringBuilder passphrase = new StringBuilder();
            if (letters.length != wordCount) {
                System.out.println("Acronym length does match passphrase length. Operation aborted.");
            }
            for (int i = 0; i < wordCount; i++) {
                String append;
                if (i > 0) {
                    passphrase.append("-");
                }
                do {
                    append = wordList.get(random.nextInt(wordList.size()));
                } while (!((String.valueOf(append.charAt(0)).equalsIgnoreCase(letters[i]))));
                passphrase.append(append);
            }
            logAction("Random passphrase generated.");
            return passphrase.toString();
        }
        private String generatePassword() {
            StringBuilder allCharacterPool = new StringBuilder();
            LinkedList < Character > requiredCharacters = new LinkedList < > ();
            Random random = new Random();
            System.out.print("Include uppercase letters? (Y/N): ");
            if (reader.nextLine().equalsIgnoreCase("Y")) {
                allCharacterPool.append(uppercase);
                requiredCharacters.add(randomCharFrom(uppercase));
            }
            System.out.print("Include lowercase letters? (Y/N): ");
            if (reader.nextLine().equalsIgnoreCase("Y")) {
                allCharacterPool.append(lowercase);
                requiredCharacters.add(randomCharFrom(lowercase));
            }
            System.out.print("Include numbers? (Y/N): ");
            if (reader.nextLine().equalsIgnoreCase("Y")) {
                allCharacterPool.append(numbers);
                requiredCharacters.add(randomCharFrom(numbers));
            }
            System.out.print("Include symbols? (Y/N): ");
            if (reader.nextLine().equalsIgnoreCase("Y")) {
                allCharacterPool.append(symbols);
                requiredCharacters.add(randomCharFrom(symbols));
            }
            if (allCharacterPool.length() == 0) {
                System.out.println("Please select at least one character type.");
                return "";
            }
            System.out.print("Enter the desired password length: ");
            int length = reader.nextInt();
            if (length < requiredCharacters.size()) {
                System.out.println("Password length is too short to include all specified character types.");
                return "";
            }
            StringBuilder password = new StringBuilder(length);
            for (char c: requiredCharacters) {
                password.append(c);
            }
            for (int i = requiredCharacters.size(); i < length; i++) {
                int index = random.nextInt(allCharacterPool.length());
                password.append(allCharacterPool.charAt(index));
            }
            return shuffle(password.toString(), random);
        }
        private String testPassword() {
            SecureRandom random = new SecureRandom();
            StringBuilder password = new StringBuilder();
            for (int i = 0; i < random.nextInt(16) + 5; i++) { // from length 5 to 20
                char check = characters.charAt(random.nextInt(characters.length()));
                if (check != '"') { // no quotes so they don't mess anything up
                    password.append(check);
                }
            }
            return password.toString();
        }
        private static char randomCharFrom(String characters) {
            Random random = new Random();
            return characters.charAt(random.nextInt(characters.length()));
        }
        private static String shuffle(String input, Random random) { // so not all required characters are always in beginning
            LinkedList < Character > characters = new LinkedList < > ();
            for (char c: input.toCharArray()) {
                characters.add(c); // add chars from input to linked list
            }
            StringBuilder shuffled = new StringBuilder(input.length());
            while (!characters.isEmpty()) {
                int randIndex = random.nextInt(characters.size()); // pick random char in input characters
                shuffled.append(characters.remove(randIndex)); // append it to shuffled string (random order)
            }
            return shuffled.toString();
        }
        private int getLength() {
            int length = 0;
            while (true) {
                try {
                    length = Integer.parseInt(reader.nextLine());
                    if (length > 0) {
                        break;
                    } else {
                        System.out.println("Please enter a positive integer.");
                    }
                } catch (Exception e) {
                    System.out.println("Invalid input. Please enter a positive integer.");
                }
            }
            return length;
        }
        public void displayAllPasswords(String adminPassword) {
            if (this.adminPassword != null && this.adminPassword.equals(adminPassword)) {
                System.out.println("All stored passwords:");
                for (String username: vault.keySet()) {
                    String password = vault.get(username);
                    if (password != null) {
                        System.out.println("Username: " + username + ", Password: " + password);
                    } else {
                        System.out.println("Username: " + username + ", Password: null");
                    }
                }
            } else {
                logAction("All passwords displayed.");
                System.out.println("Invalid admin password.");
            }
        }
        public void searchPasswordByUsername() {
            System.out.print("Enter admin password to search for usernames: ");
            String inputAdminPassword = reader.nextLine();
            if (this.adminPassword != null && this.adminPassword.equals(inputAdminPassword)) {
                System.out.print("Enter substring to search: ");
                String searchString = reader.nextLine();
                boolean found = false; // was it found
                System.out.println("Matching usernames and passwords:");
                for (Map.Entry < String, String > entry: vault.entrySet()) { // because we want the key and the value
                    String username = entry.getKey();
                    String password = entry.getValue();
                    if (username.contains(searchString)) { // doesn't have to be a perfect match
                        found = true; // set 'found' flag to true
                        if (password != null) {
                            System.out.println("Username: " + username + ", Password: " + password); // print the
                            password
                            if not null
                        } else {
                            System.out.println("Username: " + username + ", Password: null"); // print null if the
                            password is null
                        }
                        logAction("Password viewed for user: " + username);
                    }
                    if (!found) {}
                }
                System.out.println("No usernames found containing the string: " + searchString);
            } else {
                System.out.println("Invalid admin password. Access denied.");
            }
        }
        public void setAdminPassword(String currentPassword) {
            if (this.adminPassword != null && this.adminPassword.equals(currentPassword)) {
                System.out.print("Enter new admin password: ");
                String newAdminPassword = reader.nextLine();
                this.adminPassword = newAdminPassword;
                saveAdminPassword();
                System.out.println("Admin password set.");
                logAction("Admin password changed successfully.");
            } else {
                System.out.println("Current admin password is incorrect.");
            }
        }
        public void undoLastAction() {
            if (actionHistory.isEmpty()) {
                System.out.println("Nothing to undo.");
                return;
            }
            String lastAction = actionHistory.pop(); // pops action
            String[] parts = lastAction.split(","); // splits by comma
            if (parts.length < 3) {
                System.out.println("Invalid action format. Cannot undo: " + lastAction);
                actionHistory.push(lastAction); // pushes back onto stack if invalid
                return;
            }
            String actionType = parts[0];
            String username = parts[1];
            String password = parts[2];
            if ("ADD".equals(actionType)) {
                vault.remove(username); // opposite of add
                passwordList.remove(password);
                System.out.println("Undid add action for user: " + username);
            } else if ("REMOVE".equals(actionType)) {
                vault.put(username, password); // opposite of remove
                passwordList.add(password);
                System.out.println("Undid remove action for user: " + username);
            }
            savePasswordsToCSV();
            logAction("Undid last action: " + parts[0] + " " + parts[1]);
        }
        private String encrypt(String data) {
            try {
                SecureRandom random = new SecureRandom(); // crypto. secure b/c 2^128 instead of 2^48 combinations (128 vs 48 bits), doesn 't use system clock to generate seed
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // provides functionality for encryption and decryption; specifies operations to be performed on input
            byte[] iv = new byte[cipher.getBlockSize()]; // byte array of block size required by CBC
            random.nextBytes(iv); // randomly generates iv
            IvParameterSpec ivWrap = new IvParameterSpec(iv); // wraps raw IV so it can be passed to cipher
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivWrap); // initializes cipher in encryption mode with given ivWrap, encryption key
            byte[] encrypted = cipher.doFinal(data.getBytes()); // converts input data into bytes and encrypts it ("encrypted" holds ciphertext)
            ByteBuffer buffer = ByteBuffer.allocate(iv.length + encrypted.length); // bytebuffer of size (iv + encrypted) is used to store iv and encrypted text together
            buffer.put(iv); // putting iv in buffer
            buffer.put(encrypted); // putting encrypted in buffer (stored together with iv for ease of use and split when necessary)
    return Base64.getEncoder().encodeToString(buffer.array()); //convert to ASCII to store in plaintext w/o corruption / errors b / c encrypted typically has unreadable chars
} catch (Exception e) {
    System.out.println("Encryption error: " + e.getMessage());
    return null;
}
}
private String decrypt(String encryptedData) {
    try {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // provides functionality for encryption and decryption; specifies operations to be performed on input
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData); // converts back to raw byte data from ASCII characters
        ByteBuffer buffer = ByteBuffer.wrap(encryptedBytes); // wraps encrypted + iv
        byte[] iv = new byte[cipher.getBlockSize()]; // byte array of block size required by CBC
        buffer.get(iv); // separate and get the iv from the iv + encrypted
        byte[] encrypted = new byte[buffer.remaining()]; // byte array of size of buffer left
        buffer.get(encrypted); // separate and get the encrypted from the iv + encrypted
        IvParameterSpec ivSpec = new IvParameterSpec(iv); // wraps raw IV so it can be passed to cipher
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec); // initializes cipher in decryption mode with given ivWrap, encryption key
        byte[] decrypted = cipher.doFinal(encrypted); // converts encrypted byte data into decrypted byte data
        return new String(decrypted); // converts decrypted bytes into readable string (decrypted already represents plaintext password w / o any weird chars so we don 't need base64)
    } catch (Exception e) {
        System.out.println("Decryption error: " + e.getMessage());
        return null;
    }
}
private boolean requestAdminPassword() {
    int attempts = 0;
    int tries = 0;
    while (true) {
        if (attempts < 3) {
            if (tries > 0 && attempts == 0) {
                System.out.print("Flush input (press Enter): "); // gets rid of incomplete lines typed during
                lockout
                @SuppressWarnings("unused")
                String trash = reader.nextLine();
                System.out.println("Enter admin password:");
                String input = reader.nextLine();
                if (input.equals(adminPassword)) {
                    System.out.println("Access granted.");
                    return true;
                } else {
                    attempts++;
                    System.out.println("Incorrect password. Attempts left: " + (3 - attempts));
                }
            } else {
                System.out.println("Enter admin password:");
                String input = reader.nextLine();
                if (input.equals(adminPassword)) {
                    System.out.println("Access granted.");
                    return true;
                } else {
                    attempts++;
                    System.out.println("Incorrect password. Attempts left: " + (3 - attempts));
                }
            }
        } else {
            System.out.println("Too many incorrect attempts. Locking out for 5 seconds.");
            lockout(); // lockout user
            attempts = 0; // reset attempts after lockout
            tries++;
        }
    }
}
private void lockout() {
    long lockoutEndTime = System.currentTimeMillis() + 5000;
    long lastSecond = -1;
    while (System.currentTimeMillis() < lockoutEndTime) {
        long remainingTime = ((lockoutEndTime - System.currentTimeMillis()) / 1000) + 1; // b/c of division
        if (remainingTime != lastSecond) { // only update the countdown when the second changes
            System.out.print("\rLockout in progress. Time remaining: " + remainingTime + " seconds.");
            lastSecond = remainingTime;
        }
        try {
            if (System.in.available() > 0) {
                System.in.read(new byte[System.in.available()]); // clear the input buffer so nothing during
                lockout is read as admin password(although doesn 't clear incomplete lines)
                    System.out.print("\033[1F\033[K"); System.out.flush(); System.out.print("\rLockout in progress. Time remaining: " + remainingTime + " seconds.");
                }
            } catch (IOException e) {
                System.out.println("Issue clearing input: " + e.getMessage());
            }
            delay(10); // avoid lag
        }
        flushInputBuffer(); // flush
        delay(50); // allows flush to catch any stray input at end of lockout period
        flushInputBuffer(); // flush again to be sure
        System.out.println("\nLockout over. You may try entering the password again.");
    }
    private void flushInputBuffer() {
        try {}
        while (System.in.available() > 0) {
            System.in.read(new byte[System.in.available()]);
        } catch (IOException e) {
            System.out.println("Issue clearing input buffer: " + e.getMessage());
        }
    }
    private static void typingEffect(String text) {
        for (char c: text.toCharArray()) {
            System.out.print(c);
            delay(50);
        }
        System.out.println();
    }
    private static void delay(int milliseconds) {
        long start = System.currentTimeMillis();
        while (System.currentTimeMillis() - start < milliseconds) {
            // do nothing
        }
    }
    public static void main(String[] args) {
        PasswordVault passwordVault = new PasswordVault();
        passwordVault.requestAdminPassword();
        int choice = -1;
        System.out.println("Enter test mode? (Y/N)"); // generates and stores 50 random username-password pairs
        String test = reader.nextLine();
        if (test.equalsIgnoreCase("Y")) {
            SecureRandom random = new SecureRandom(); // had some issues here where 1 or 2/50 passwords would be a different length than the rest (I think) b / c of the system time - based seeding with regular Random so we switched
            to SecureRandom
            for (int i = 0; i < 50; i++) {
                StringBuilder username = new StringBuilder("user");
                for (int j = 0; j < 5; j++) {
                    char check = characters.charAt(random.nextInt(characters.length()));
                    if (check != '"') { // no quotes so they don't mess anything up
                        username.append(check);
                    }
                }
                String password = passwordVault.testPassword();
                passwordVault.addTestPassword(username.toString(), password);
            }
        }
        do {
            System.out.println();
            System.out.println("---- Menu ----");
            System.out.println();
            System.out.println("1. Add/Change Password");
            System.out.println("2. Remove Password");
            System.out.println("3. Generate Random Password");
            System.out.println("4. Display All Passwords");
            System.out.println("5. Set Administrator Password");
            System.out.println("6. Undo Last Action");
            System.out.println("7. Search Passwords By Username");
            System.out.println("8. View Logs");
            System.out.println("9. Export Passwords");
            System.out.println("10. Exit Program");
            System.out.println();
            System.out.print("Choose an option: ");
            try {
                choice = reader.nextInt();
                reader.nextLine();
                switch (choice) {
                    case 1:
                        System.out.print("Enter username: ");
                        String username = reader.nextLine();
                        passwordVault.addPassword(username);
                        break;
                    case 2:
                        System.out.print("Enter username to remove: ");
                        String removeUser = reader.nextLine();
                        passwordVault.removePassword(removeUser);
                        break;
                    case 3:
                        String generatedPassword = passwordVault.generateRandomPassword();
                        System.out.println("Generated Password: " + generatedPassword);
                        break;
                    case 4:
                        System.out.print("Enter admin password to view all passwords: ");
                        String adminPassInput = reader.nextLine();
                        passwordVault.displayAllPasswords(adminPassInput);
                        break;
                    case 5:
                        System.out.print("Enter current admin password: ");
                        String currentAdminPass = reader.nextLine();
                        passwordVault.setAdminPassword(currentAdminPass);
                        break;
                    case 6:
                        passwordVault.undoLastAction();
                        break;
                    case 7:
                        passwordVault.searchPasswordByUsername();
                        break;
                    case 8:
                        System.out.print("Enter admin password to view logs: ");
                        String logAdminPass = reader.nextLine();
                        passwordVault.viewLogs(logAdminPass);
                        break;
                    case 9:
                        System.out.println("Enter the file path.");
                        String filePath = reader.nextLine();
                        passwordVault.export(filePath);
                        break;
                    case 10:
                        typingEffect("Program exited.");
                        passwordVault.savePasswordsToCSV();
                        break;
                    case 99:
                        System.out.print("\033c"); // clear screen discreetly
                        System.out.flush();
                        break;
                    default:
                        System.out.println("Invalid option. Please try again.");
                        break;
                }
            } catch (InputMismatchException e) {
                System.out.println("Invalid input. Please enter a number.");
                reader.nextLine();
            }
        } while (choice != 10);
        reader.close();
    }
    private void logAction(String action) {
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()); // something from stack overflow
        PrintWriter pw = null;
        try {
            pw = new PrintWriter(new FileWriter(logFile, true)); // puts writer in append mode (so it doesn't overwrite existing content)
        pw.println("[" + timestamp + "] " + action);
    } catch (IOException e) {
        System.out.println("Error logging action: " + e.getMessage());
    } finally {
        if (pw != null) {
            pw.close();
        }
    }
}
public void viewLogs(String inputAdminPassword) {
    if (this.adminPassword != null && this.adminPassword.equals(inputAdminPassword)) {
        System.out.println("---- Log History ----");
        try (BufferedReader br = new BufferedReader(new FileReader(logFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            System.out.println("Error reading log file: " + e.getMessage());
        }
    } else {
        logAction("Action logs viewed.");
        System.out.println("Invalid admin password. Access denied.");
    }
}
}
