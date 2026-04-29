package service;

import model.Ticket;
import java.io.*;
import java.util.*;

/**
 * This class handles everything related to tickets:
 * creating, assigning, updating, deleting, and fetching tickets.
 */
public class TicketService {

    // File where tickets are stored
    private static final String FILE = "tickets.txt";

    /**
     * Generates a unique ticket ID based on the user
     * and how many tickets they have already created.
     * Example: IDrahul1, IDrahul2
     */
    private static String generateTicketId(String username) throws Exception {

        File file = new File(FILE);
        int count = 0;

        // Count how many tickets this user already has
        if (file.exists()) {
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                String line;

                while ((line = br.readLine()) != null) {

                    String[] parts = parseTicketLine(line);

                    if (parts != null && parts[4].equals(username)) {
                        count++;
                    }
                }
            }
        }

        return "ID" + username + (count + 1);
    }

    /**
     * Creates a new ticket and assigns it to support staff.
     */
    public static void createTicket(String title, String desc, String user) throws Exception {

        List<String> supports = AuthService.getSupportUsers();

        if (supports.isEmpty()) {
            throw new Exception("No support staff available!");
        }

        // Round-robin assignment (fair distribution)
        int lastIndex = getLastAssignedIndex();
        int newIndex = (lastIndex + 1) % supports.size();

        String assignedTo = supports.get(newIndex);
        saveLastAssignedIndex(newIndex);

        String ticketId = generateTicketId(user);

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(FILE, true))) {
            bw.write(ticketId + "," + title + "," + desc + ",Pending," + user + "," + assignedTo);
            bw.newLine();
        }
    }

    /**
     * Reads the last assigned support index from file.
     */
    private static int getLastAssignedIndex() throws Exception {

        File file = new File("last_index.txt");

        if (!file.exists()) return -1;

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line = br.readLine();
            return (line != null) ? Integer.parseInt(line) : -1;
        }
    }

    /**
     * Saves the latest assigned support index.
     */
    private static void saveLastAssignedIndex(int index) throws Exception {

        try (BufferedWriter bw = new BufferedWriter(new FileWriter("last_index.txt"))) {
            bw.write(String.valueOf(index));
        }
    }

    /**
     * Safely parses a ticket line from file.
     * Handles cases where description may contain commas.
     */
    private static String[] parseTicketLine(String line) {

        if (line == null || line.isEmpty()) return null;

        String[] parts = line.split(",");
        if (parts.length < 6) return null;

        String id = parts[0];
        String title = parts[1];
        String assignedTo = parts[parts.length - 1];
        String user = parts[parts.length - 2];
        String status = parts[parts.length - 3];

        // Rebuild description (since it may contain commas)
        StringBuilder desc = new StringBuilder();
        for (int i = 2; i <= parts.length - 4; i++) {
            if (i > 2) desc.append(",");
            desc.append(parts[i]);
        }

        return new String[]{id, title, desc.toString(), status, user, assignedTo};
    }

    /**
     * Returns all tickets.
     */
    public static List<Ticket> getTickets() throws Exception {

        List<Ticket> tickets = new ArrayList<>();
        File file = new File(FILE);

        if (!file.exists()) return tickets;

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;

            while ((line = br.readLine()) != null) {

                String[] p = parseTicketLine(line);

                if (p != null) {
                    tickets.add(new Ticket(p[0], p[1], p[2], p[3], p[4], p[5]));
                }
            }
        }

        return tickets;
    }

    /**
     * Updates ticket status (with validation rules).
     */
    public static void updateStatus(String id, String username, String newStatus) throws Exception {

        File file = new File(FILE);
        List<String> lines = new ArrayList<>();
        boolean found = false;

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {

            String line;

            while ((line = br.readLine()) != null) {

                String[] p = parseTicketLine(line);

                if (p == null) {
                    lines.add(line);
                    continue;
                }

                String ticketId = p[0];
                String assignedTo = p[5];
                String currentStatus = p[3];

                if (ticketId.equals(id) && assignedTo.equals(username)) {

                    found = true;

                    // Valid status transitions
                    if (newStatus.equals("In Progress") && currentStatus.equals("Pending")) {
                        p[3] = "In Progress";
                    }
                    else if (newStatus.equals("Resolved") &&
                             (currentStatus.equals("Pending") || currentStatus.equals("In Progress"))) {
                        p[3] = "Resolved";
                    }
                    else if (!newStatus.equals(currentStatus)) {
                        throw new Exception("Invalid status change: " +
                                currentStatus + " → " + newStatus);
                    }

                    line = String.join(",", p);
                }

                lines.add(line);
            }
        }

        if (!found) {
            throw new Exception("Ticket not found or not assigned to you!");
        }

        // Rewrite file with updated data
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(file))) {
            for (String l : lines) {
                bw.write(l);
                bw.newLine();
            }
        }
    }

    /**
     * Deletes a ticket (only if resolved and assigned to the user).
     */
    public static void deleteTicket(String id, String username) throws Exception {

        File file = new File(FILE);
        List<String> lines = new ArrayList<>();
        boolean found = false;

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {

            String line;

            while ((line = br.readLine()) != null) {

                String[] p = parseTicketLine(line);

                if (p == null) {
                    lines.add(line);
                    continue;
                }

                String ticketId = p[0];
                String assignedTo = p[5];
                String status = p[3];

                if (ticketId.equals(id) && assignedTo.equals(username)) {

                    if (!status.equals("Resolved")) {
                        throw new Exception("Only resolved tickets can be deleted!");
                    }

                    found = true;
                    continue; // skip → delete
                }

                lines.add(line);
            }
        }

        if (!found) {
            throw new Exception("Ticket not found / not assigned / not resolved!");
        }

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(file))) {
            for (String l : lines) {
                bw.write(l);
                bw.newLine();
            }
        }
    }

    /**
     * Fetch a single ticket by ID.
     */
    public static Ticket getTicketById(String id) throws Exception {

        for (Ticket t : getTickets()) {
            if (t.getId().equals(id)) {
                return t;
            }
        }

        return null;
    }
}