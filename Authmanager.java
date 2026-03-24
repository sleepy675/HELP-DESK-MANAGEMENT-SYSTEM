package auth;

import dao.UserDAO;
import model.User;
import util.AppUtils;

import java.util.Optional;



public class AuthManager {

    private static AuthManager instance;
    private UserDAO userDAO;
    private User currentUser; // cuurently loggedd in user

    // Private constructor (Singleton)
    private AuthManager(UserDAO userDAO) {
        this.userDAO = userDAO;
        this.currentUser = null;
    }

    // Get single instance
    public static AuthManager getInstance(UserDAO userDAO) {
        if (instance == null) {
            instance = new AuthManager(userDAO);
        }
        return instance;
    }

    public static void reset() {
        instance = null;
    }

    // Login method
    public LoginResult login(String email, String rawPassword) {

        // Step 1: Validate email
        if (!AppUtils.isValidEmail(email)) {
            return new LoginResult(false, "Invalid email format", null);
        }

        // Step 2: Find user
        Optional<User> userOpt = userDAO.findByEmail(email);
        if (!userOpt.isPresent()) {
            return new LoginResult(false, "No account found with that email", null);
        }

        User user = userOpt.get();

        // Step 3: Check if active
        if (!user.isActive()) {
            return new LoginResult(false, "Account is deactivated. Contact admin.", null);
        }

        // Step 4: Verify password
        if (!AppUtils.verifyPassword(rawPassword, user.getPasswordHash())) {
            return new LoginResult(false, "Incorrect password", null);
        }

        // Step 5: Success
        currentUser = user;
        return new LoginResult(true, "Login successful", user);
    }

    // Logout
    public void logout() {
        currentUser = null;
    }

    // Get current user
    public User getCurrentUser() {
        return currentUser;
    }

    // Check login status
    public boolean isLoggedIn() {
        return currentUser != null;
    }

    // Result class
    public static class LoginResult {
        public final boolean success;
        public final String message;
        public final User user;

        public LoginResult(boolean success, String message, User user) {
            this.success = success;
            this.message = message;
            this.user = user;
        }
    }
}