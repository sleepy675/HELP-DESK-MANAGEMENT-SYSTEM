package ui;

import javax.swing.*;
import javax.swing.table.*;
import service.TicketService;
import model.Ticket;

import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Support Dashboard
 * 
 * Allows support staff to:
 * - View assigned tickets
 * - Update ticket status
 * - Auto process tickets
 * - Delete resolved tickets
 * - View history
 */
public class SupportDashboard extends JFrame {

    private JTable table;
    private DefaultTableModel model;
    private String username;

    // Status constants (avoids hardcoding strings everywhere)
    private static final String PENDING = "Pending";
    private static final String IN_PROGRESS = "In Progress";
    private static final String RESOLVED = "Resolved";

    public SupportDashboard(String username) {

        this.username = username;

        setTitle("Support Dashboard - " + username);
        setSize(900, 600);
        setLayout(new BorderLayout());
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        add(createTablePanel(), BorderLayout.CENTER);
        add(createButtonPanel(), BorderLayout.SOUTH);
        add(createStatusBar(), BorderLayout.NORTH);

        loadTickets();

        setVisible(true);
    }

    /**
     * Creates ticket table
     */
    private JScrollPane createTablePanel() {

        String[] cols = {"Select", "ID", "Title", "User", "Status"};

        model = new DefaultTableModel(cols, 0) {
            public Class<?> getColumnClass(int col) {
                return col == 0 ? Boolean.class : String.class;
            }
        };

        table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setDefaultRenderer(Object.class, new StatusRenderer());

        return new JScrollPane(table);
    }

    /**
     * Bottom panel with all actions
     */
    private JPanel createButtonPanel() {

        JPanel panel = new JPanel(new GridLayout(2, 5, 10, 10));

        JButton refreshBtn = createButton("Refresh", e -> {
            loadTickets();
            updateStatus("Refreshed");
        });

        JButton startBtn = createButton("Start Work", e -> updateTickets(IN_PROGRESS));
        JButton resolveBtn = createButton("Resolve", e -> updateTickets(RESOLVED));
        JButton autoBtn = createButton("Auto Process", e -> autoProcess());
        JButton historyBtn = createButton("History", e -> showHistory());

        JButton selectPendingBtn = createButton("Select Pending", e -> selectPending());
        JButton deselectBtn = createButton("Deselect All", e -> deselectAll());
        JButton deleteBtn = createButton("Delete Resolved", e -> deleteResolved());

        JButton logoutBtn = createButton("Logout", e -> {
            dispose();
            new LoginUI();
        });

        panel.add(refreshBtn);
        panel.add(startBtn);
        panel.add(resolveBtn);
        panel.add(autoBtn);
        panel.add(historyBtn);
        panel.add(selectPendingBtn);
        panel.add(deselectBtn);
        panel.add(deleteBtn);
        panel.add(logoutBtn);

        return panel;
    }

    /**
     * Status bar at top
     */
    private JLabel createStatusBar() {
        return new JLabel("Ready");
    }

    private void updateStatus(String text) {
        ((JLabel) getContentPane().getComponent(2)).setText(text);
    }

    /**
     * Utility method to create buttons
     */
    private JButton createButton(String text, java.awt.event.ActionListener action) {
        JButton btn = new JButton(text);
        btn.addActionListener(action);
        return btn;
    }

    /**
     * Load tickets assigned to this support user
     */
    private void loadTickets() {

        model.setRowCount(0);

        try {
            for (Ticket t : TicketService.getTickets()) {
                if (username.equals(t.getAssignedTo())) {
                    model.addRow(new Object[]{
                            false,
                            t.getId(),
                            t.getTitle(),
                            t.getUser(),
                            t.getStatus()
                    });
                }
            }
        } catch (Exception ignored) {}
    }

    /**
     * Get selected ticket IDs (checkbox OR row selection)
     */
    private List<String> getSelectedIds() {

        Set<String> ids = new LinkedHashSet<>();

        // From checkbox
        for (int i = 0; i < model.getRowCount(); i++) {
            if (Boolean.TRUE.equals(model.getValueAt(i, 0))) {
                ids.add(model.getValueAt(i, 1).toString());
            }
        }

        // From row selection (fallback)
        if (ids.isEmpty()) {
            for (int row : table.getSelectedRows()) {
                ids.add(model.getValueAt(row, 1).toString());
            }
        }

        return new ArrayList<>(ids);
    }

    /**
     * Update selected tickets to given status
     */
    private void updateTickets(String newStatus) {

        List<String> ids = getSelectedIds();
        if (ids.isEmpty()) return;

        for (String id : ids) {
            try {
                TicketService.updateStatus(id, username, newStatus);
            } catch (Exception ignored) {}
        }

        loadTickets();
    }

    /**
     * Automatically process pending tickets
     */
    private void autoProcess() {

        List<String> ids = getSelectedIds();
        if (ids.isEmpty()) return;

        List<Ticket> tickets = getAllTickets();

        for (String id : ids) {
            Ticket t = findTicket(tickets, id);

            if (t != null && PENDING.equals(t.getStatus())) {
                try {
                    TicketService.updateStatus(id, username, IN_PROGRESS);
                    TicketService.updateStatus(id, username, RESOLVED);
                } catch (Exception ignored) {}
            }
        }

        loadTickets();
    }

    /**
     * Delete resolved tickets
     */
    private void deleteResolved() {

        List<String> ids = getSelectedIds();
        if (ids.isEmpty()) return;

        List<Ticket> tickets = getAllTickets();

        for (String id : ids) {
            Ticket t = findTicket(tickets, id);

            if (t != null && RESOLVED.equals(t.getStatus())) {
                try {
                    TicketService.deleteTicket(id, username);
                } catch (Exception ignored) {}
            }
        }

        loadTickets();
    }

    /**
     * Show history of resolved tickets
     */
    private void showHistory() {

        try {
            String history = TicketService.getTickets().stream()
                    .filter(t -> username.equals(t.getAssignedTo()) && RESOLVED.equals(t.getStatus()))
                    .map(t -> t.getId() + " | " + t.getTitle())
                    .collect(Collectors.joining("\n"));

            JOptionPane.showMessageDialog(this,
                    history.isEmpty() ? "No history available" : history);

        } catch (Exception ignored) {}
    }

    /**
     * Select only pending tickets
     */
    private void selectPending() {

        for (int i = 0; i < model.getRowCount(); i++) {
            if (PENDING.equals(model.getValueAt(i, 4))) {
                model.setValueAt(true, i, 0);
            }
        }
    }

    /**
     * Deselect all rows
     */
    private void deselectAll() {
        for (int i = 0; i < model.getRowCount(); i++) {
            model.setValueAt(false, i, 0);
        }
    }

    /**
     * Helper: get all tickets safely
     */
    private List<Ticket> getAllTickets() {
        try {
            return TicketService.getTickets();
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    /**
     * Helper: find ticket by ID
     */
    private Ticket findTicket(List<Ticket> list, String id) {
        return list.stream()
                .filter(t -> t.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    /**
     * Custom renderer to color rows based on status
     */
    class StatusRenderer extends DefaultTableCellRenderer {

        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int col) {

            Component c = super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, col
            );

            if (!isSelected) {
                String status = table.getValueAt(row, 4).toString();

                switch (status) {
                    case PENDING:
                        c.setBackground(Color.PINK);
                        break;
                    case IN_PROGRESS:
                        c.setBackground(Color.YELLOW);
                        break;
                    case RESOLVED:
                        c.setBackground(Color.GREEN);
                        break;
                    default:
                        c.setBackground(Color.WHITE);
                }
            }

            return c;
        }
    }
}