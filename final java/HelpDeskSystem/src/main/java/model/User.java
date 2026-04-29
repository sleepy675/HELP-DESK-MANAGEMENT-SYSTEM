package model;

/**
 * This class represents a user in the Help Desk system.
 * A user can be an admin, staff member, or customer,
 * depending on their role.
 */
public class User {

    // Username used for login and identification
    private String username;

    // Password for authentication (should ideally be stored securely)
    private String password;

    // Role defines what the user can do (admin, staff, customer)
    private String role;

    /**
     * Constructor: creates a new user with basic details.
     */
    public User(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    // ----- Getter Methods -----

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getRole() {
        return role;
    }
}