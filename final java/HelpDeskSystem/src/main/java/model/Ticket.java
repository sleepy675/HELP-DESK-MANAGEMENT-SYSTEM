package model;

/**
 * This class represents a support ticket in the Help Desk system.
 * Each ticket contains basic details like title, description,
 * current status, the user who created it, and the staff assigned.
 */
public class Ticket {

    // Unique ticket ID (e.g., "TCK-101")
    private String id;

    // Short title describing the issue
    private String title;

    // Detailed explanation of the problem
    private String description;

    // Current status (Open, In Progress, Closed, etc.)
    private String status;

    // Name of the user who created the ticket
    private String user;

    // Staff member assigned to resolve the issue
    private String assignedTo;

    /**
     * Constructor: used when creating a new ticket.
     */
    public Ticket(String id, String title, String description,
                  String status, String user, String assignedTo) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.status = status;
        this.user = user;
        this.assignedTo = assignedTo;
    }

    // ----- Getter Methods -----

    public String getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public String getStatus() {
        return status;
    }

    public String getUser() {
        return user;
    }

    public String getAssignedTo() {
        return assignedTo;
    }

    /**
     * Updates the status of the ticket.
     * Example: Open → In Progress → Closed
     */
    public void setStatus(String status) {
        this.status = status;
    }
}