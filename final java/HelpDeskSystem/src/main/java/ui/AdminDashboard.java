package ui;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import service.AuthService;
import service.TicketService;
import model.Ticket;
import model.User;

import java.awt.*;
import java.util.List;

/**
 * Admin Dashboard UI
 * 
 * This screen allows admin to:
 * - View all tickets
 * - View all users and their ticket stats
 * - View support staff workload
 * - Filter tickets
 * - Refresh system data
 * - Logout
 */
public class AdminDashboard extends JFrame {

    private JTable ticketsTable, usersTable, supportTable;
    private DefaultTableModel ticketsModel, usersModel, supportModel;
    private JLabel statsLabel;

    public AdminDashboard() {

        setTitle("Help Desk System - Admin Dashboard");
        setSize(1200, 750);
        setLayout(new BorderLayout());
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // Top section (statistics)
        add(createTopPanel(), BorderLayout.NORTH);

        // Center section (tabs)
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("All Tickets", createTicketsPanel());
        tabs.addTab("All Users", createUsersPanel());
        tabs.addTab("Support Staff", createSupportPanel());

        add(tabs, BorderLayout.CENTER);

        // Bottom section (buttons)
        add(createBottomPanel(), BorderLayout.SOUTH);

        // Load data initially
        refreshAllData();

        setVisible(true);
    }

    /**
     * Creates top panel showing overall system stats
     */
    private JPanel createTopPanel() {

        JPanel panel = new JPanel();
        panel.setBackground(UITheme.PRIMARY_COLOR);
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        statsLabel = new JLabel("Loading statistics...");
        statsLabel.setFont(UITheme.STATS_FONT);
        statsLabel.setForeground(Color.WHITE);

        panel.add(statsLabel);
        return panel;
    }

    /**
     * Panel to display all tickets with filtering option
     */
    private JPanel createTicketsPanel() {

        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        String[] cols = {"ID", "Title", "User", "Assigned To", "Status"};

        ticketsModel = new DefaultTableModel(cols, 0) {
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };

        ticketsTable = new JTable(ticketsModel);
        UITheme.styleTable(ticketsTable);

        panel.add(new JScrollPane(ticketsTable), BorderLayout.CENTER);

        // Filter section
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filterPanel.setBorder(BorderFactory.createTitledBorder("Filter Tickets"));

        JComboBox<String> statusBox = new JComboBox<>(
                new String[]{"All", "Pending", "In Progress", "Resolved"}
        );
        UITheme.styleComboBox(statusBox);

        JButton filterBtn = new JButton("Filter");
        UITheme.styleButton(filterBtn);
        filterBtn.addActionListener(e ->
                loadTickets((String) statusBox.getSelectedItem())
        );

        JButton resetBtn = new JButton("Show All");
        UITheme.styleButton(resetBtn);
        resetBtn.addActionListener(e -> loadTickets("All"));

        filterPanel.add(new JLabel("Status:"));
        filterPanel.add(statusBox);
        filterPanel.add(filterBtn);
        filterPanel.add(resetBtn);

        panel.add(filterPanel, BorderLayout.NORTH);

        return panel;
    }

    /**
     * Panel to display all users with ticket stats
     */
    private JPanel createUsersPanel() {

        JPanel panel = new JPanel(new BorderLayout());

        String[] cols = {"Username", "Total", "Pending", "In Progress", "Resolved"};

        usersModel = new DefaultTableModel(cols, 0) {
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };

        usersTable = new JTable(usersModel);
        UITheme.styleTable(usersTable);

        panel.add(new JScrollPane(usersTable), BorderLayout.CENTER);

        JButton viewBtn = new JButton("View User Tickets");
        UITheme.styleButton(viewBtn);

        viewBtn.addActionListener(e -> {
            int row = usersTable.getSelectedRow();

            if (row == -1) {
                showWarning("Please select a user first!");
                return;
            }

            String username = usersModel.getValueAt(row, 0).toString();
            showUserTickets(username);
        });

        JPanel bottom = new JPanel();
        bottom.add(viewBtn);

        panel.add(bottom, BorderLayout.SOUTH);

        return panel;
    }

    /**
     * Panel to display support staff workload
     */
    private JPanel createSupportPanel() {

        JPanel panel = new JPanel(new BorderLayout());

        String[] cols = {"Support", "Total", "Pending", "In Progress", "Resolved"};

        supportModel = new DefaultTableModel(cols, 0) {
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };

        supportTable = new JTable(supportModel);
        UITheme.styleTable(supportTable);

        panel.add(new JScrollPane(supportTable), BorderLayout.CENTER);

        JButton viewBtn = new JButton("View Support Tickets");
        UITheme.styleButton(viewBtn);

        viewBtn.addActionListener(e -> {
            int row = supportTable.getSelectedRow();

            if (row == -1) {
                showWarning("Please select a support staff!");
                return;
            }

            String name = supportModel.getValueAt(row, 0).toString();
            showSupportTickets(name);
        });

        JPanel bottom = new JPanel();
        bottom.add(viewBtn);

        panel.add(bottom, BorderLayout.SOUTH);

        return panel;
    }

    /**
     * Bottom panel with refresh and logout buttons
     */
    private JPanel createBottomPanel() {

        JPanel panel = new JPanel();

        JButton refreshBtn = new JButton("Refresh");
        UITheme.styleButton(refreshBtn);
        refreshBtn.addActionListener(e -> refreshAllData());

        JButton logoutBtn = new JButton("Logout");
        UITheme.styleDangerButton(logoutBtn);

        logoutBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(
                    this, "Are you sure you want to logout?", "Logout",
                    JOptionPane.YES_NO_OPTION
            );

            if (confirm == JOptionPane.YES_OPTION) {
                dispose();
                new LoginUI();
            }
        });

        panel.add(refreshBtn);
        panel.add(logoutBtn);

        return panel;
    }

    /**
     * Refresh all dashboard data
     */
    private void refreshAllData() {
        updateStatistics();
        loadTickets("All");
        loadUsers();
        loadSupportStaff();
    }

    /**
     * Update top statistics bar
     */
    private void updateStatistics() {

        try {
            List<Ticket> tickets = TicketService.getTickets();
            List<User> users = AuthService.getAllUsers();
            List<String> supports = AuthService.getSupportUsers();

            long pending = tickets.stream().filter(t -> t.getStatus().equals("Pending")).count();
            long inProg = tickets.stream().filter(t -> t.getStatus().equals("In Progress")).count();
            long resolved = tickets.stream().filter(t -> t.getStatus().equals("Resolved")).count();

            long userCount = users.stream().filter(u -> u.getRole().equals("user")).count();

            statsLabel.setText(String.format(
                    "📊 Total: %d | Pending: %d | In Progress: %d | Resolved: %d | Users: %d | Support: %d",
                    tickets.size(), pending, inProg, resolved, userCount, supports.size()
            ));

        } catch (Exception e) {
            statsLabel.setText("Error loading stats");
        }
    }

    /**
     * Load tickets into table with optional filtering
     */
    private void loadTickets(String filter) {

        ticketsModel.setRowCount(0);

        try {
            for (Ticket t : TicketService.getTickets()) {

                if (filter.equals("All") || t.getStatus().equals(filter)) {
                    ticketsModel.addRow(new Object[]{
                            t.getId(), t.getTitle(), t.getUser(),
                            t.getAssignedTo(), t.getStatus()
                    });
                }
            }

        } catch (Exception e) {
            showError("Error loading tickets: " + e.getMessage());
        }
    }

    /**
     * Load users with ticket stats
     */
    private void loadUsers() {

        usersModel.setRowCount(0);

        try {
            List<Ticket> tickets = TicketService.getTickets();

            for (User u : AuthService.getAllUsers()) {

                if (!u.getRole().equals("user")) continue;

                String name = u.getUsername();

                long total = tickets.stream().filter(t -> t.getUser().equals(name)).count();
                long pending = tickets.stream().filter(t -> t.getUser().equals(name) && t.getStatus().equals("Pending")).count();
                long inProg = tickets.stream().filter(t -> t.getUser().equals(name) && t.getStatus().equals("In Progress")).count();
                long resolved = tickets.stream().filter(t -> t.getUser().equals(name) && t.getStatus().equals("Resolved")).count();

                usersModel.addRow(new Object[]{name, total, pending, inProg, resolved});
            }

        } catch (Exception e) {
            showError("Error loading users: " + e.getMessage());
        }
    }

    /**
     * Load support staff stats
     */
    private void loadSupportStaff() {

        supportModel.setRowCount(0);

        try {
            List<Ticket> tickets = TicketService.getTickets();

            for (String s : AuthService.getSupportUsers()) {

                long total = tickets.stream().filter(t -> t.getAssignedTo().equals(s)).count();
                long pending = tickets.stream().filter(t -> t.getAssignedTo().equals(s) && t.getStatus().equals("Pending")).count();
                long inProg = tickets.stream().filter(t -> t.getAssignedTo().equals(s) && t.getStatus().equals("In Progress")).count();
                long resolved = tickets.stream().filter(t -> t.getAssignedTo().equals(s) && t.getStatus().equals("Resolved")).count();

                supportModel.addRow(new Object[]{s, total, pending, inProg, resolved});
            }

        } catch (Exception e) {
            showError("Error loading support staff: " + e.getMessage());
        }
    }

    /**
     * Utility methods for dialogs
     */
    private void showWarning(String msg) {
        JOptionPane.showMessageDialog(this, msg, "Warning", JOptionPane.WARNING_MESSAGE);
    }

    private void showError(String msg) {
        JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
    }

    /**
     * Show user tickets popup
     */
    private void showUserTickets(String username) {
        showTicketsPopup("Tickets for " + username,
                t -> t.getUser().equals(username));
    }

    /**
     * Show support tickets popup
     */
    private void showSupportTickets(String name) {
        showTicketsPopup("Tickets assigned to " + name,
                t -> t.getAssignedTo().equals(name));
    }

    /**
     * Generic popup builder
     */
    private void showTicketsPopup(String title, java.util.function.Predicate<Ticket> filter) {

        try {
            StringBuilder sb = new StringBuilder(title + "\n\n");

            for (Ticket t : TicketService.getTickets()) {
                if (filter.test(t)) {
                    sb.append("ID: ").append(t.getId())
                      .append(" | ").append(t.getTitle())
                      .append(" | ").append(t.getStatus())
                      .append("\n");
                }
            }

            JTextArea area = new JTextArea(sb.toString());
            area.setEditable(false);

            JScrollPane sp = new JScrollPane(area);
            sp.setPreferredSize(new Dimension(600, 300));

            JOptionPane.showMessageDialog(this, sp, title, JOptionPane.INFORMATION_MESSAGE);

        } catch (Exception e) {
            showError("Error: " + e.getMessage());
        }
    }
}