package service;

import model.User;
import java.io.*;
import java.util.*;

/**
 * This class handles all authentication-related operations
 * like registration, login, and fetching users.
 */
public class AuthService {

    // File where all user data is stored
    private static final String FILE = "users.txt";

    /**
     * Registers a new user.
     */
    public static void register(User user) throws Exception {

        // Prevent creating another admin manually
        if (user.getUsername().equals("admin")) {
            throw new Exception("Admin account cannot be registered manually!");
        }

        // Check if username is already taken
        if (userExists(user.getUsername())) {
            throw new Exception("Username already exists!");
        }

        // Save user details to file
        BufferedWriter bw = new BufferedWriter(new FileWriter(FILE, true));
        bw.write(user.getUsername() + "," + user.getPassword() + "," + user.getRole());
        bw.newLine();
        bw.close();
    }

    /**
     * Logs in a user by checking username and password.
     */
    public static User login(String username, String password) throws Exception {

        File file = new File(FILE);

        // If file doesn't exist, no users are registered yet
        if (!file.exists()) {
            System.out.println("No users found. Please register first.");
            return null;
        }

        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;

        while ((line = br.readLine()) != null) {

            String[] parts = line.split(",");

            // Ensure valid data format
            if (parts.length >= 3) {

                String fileUsername = parts[0].trim();
                String filePassword = parts[1].trim();
                String fileRole = parts[2].trim();

                // Match credentials
                if (fileUsername.equals(username) && filePassword.equals(password)) {
                    br.close();
                    return new User(fileUsername, filePassword, fileRole);
                }
            }
        }

        br.close();
        return null; // Login failed
    }

    /**
     * Checks if a username already exists.
     */
    private static boolean userExists(String username) throws Exception {

        File file = new File(FILE);
        if (!file.exists()) return false;

        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;

        while ((line = br.readLine()) != null) {

            String[] parts = line.split(",");

            if (parts.length > 0 && parts[0].equals(username)) {
                br.close();
                return true;
            }
        }

        br.close();
        return false;
    }

    /**
     * Returns list of all support staff usernames.
     */
    public static List<String> getSupportUsers() throws Exception {

        List<String> supports = new ArrayList<>();

        File file = new File(FILE);
        if (!file.exists()) return supports;

        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;

        while ((line = br.readLine()) != null) {

            String[] parts = line.split(",");

            // Filter users with "support" role
            if (parts.length >= 3 && parts[2].equals("support")) {
                supports.add(parts[0]);
            }
        }

        br.close();
        return supports;
    }

    /**
     * Returns all users as User objects.
     */
    public static List<User> getAllUsers() throws Exception {

        List<User> users = new ArrayList<>();

        File file = new File(FILE);
        if (!file.exists()) return users;

        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;

        while ((line = br.readLine()) != null) {

            String[] parts = line.split(",");

            if (parts.length >= 3) {
                users.add(new User(parts[0], parts[1], parts[2]));
            }
        }

        br.close();
        return users;
    }
}