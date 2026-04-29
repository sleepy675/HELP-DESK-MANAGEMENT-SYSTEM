package ui;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;

import model.Ticket;
import service.TicketService;

/**
 * User Dashboard
 * 
 * Allows users to:
 * - Create tickets
 * - View their tickets
 * - Delete tickets
 * - Refresh ticket list
 */
public class UserDashboard extends JFrame {

    private JTextField titleField;
    private JTextArea descField;
    private JTable table;
    private DefaultTableModel model;
    private JLabel statusLabel;

    private String username;

    public UserDashboard(String username) {

        this.username = username;

        setTitle("User Dashboard - " + username);
        setSize(900, 650);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        add(createMainPanel());
        setVisible(true);
    }

    /**
     * Main layout (header + split + footer)
     */
    private JPanel createMainPanel() {

        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(UITheme.BG_COLOR);

        panel.add(UITheme.createHeaderPanel("Manage Your Tickets"), BorderLayout.NORTH);
        panel.add(createSplitPane(), BorderLayout.CENTER);
        panel.add(createFooter(), BorderLayout.SOUTH);

        return panel;
    }

    /**
     * Split screen (top = create ticket, bottom = list)
     */
    private JSplitPane createSplitPane() {

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        split.setResizeWeight(0.4);

        split.setTopComponent(createCreatePanel());
        split.setBottomComponent(createListPanel());

        return split;
    }

    /**
     * Footer with status + logout
     */
    private JPanel createFooter() {

        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        statusLabel = new JLabel("Ready");
        panel.add(statusLabel, BorderLayout.WEST);

        JButton logout = new JButton("Logout");
        UITheme.styleDangerButton(logout);

        logout.addActionListener(e -> {
            dispose();
            new LoginUI();
        });

        panel.add(logout, BorderLayout.EAST);

        return panel;
    }

    /**
     * Panel to create tickets
     */
    private JPanel createCreatePanel() {

        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Create Ticket"));

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseGBC();

        // Title
        form.add(new JLabel("Title:"), gbc);
        titleField = new JTextField();
        UITheme.styleTextField(titleField);
        form.add(titleField, nextRow(gbc));

        // Description
        form.add(new JLabel("Description:"), nextRow(gbc));
        descField = new JTextArea(3, 30);
        descField.setLineWrap(true);

        JScrollPane scroll = new JScrollPane(descField);
        form.add(scroll, nextRow(gbc));

        // Buttons
        JPanel btnPanel = new JPanel();

        JButton create = new JButton("Create");
        UITheme.styleSuccessButton(create);
        create.addActionListener(e -> createTicket());

        JButton clear = new JButton("Clear");
        UITheme.styleButton(clear);
        clear.addActionListener(e -> clearFields());

        btnPanel.add(create);
        btnPanel.add(clear);

        form.add(btnPanel, nextRow(gbc));

        panel.add(form);
        return panel;
    }

    /**
     * Panel to show ticket list
     */
    private JPanel createListPanel() {

        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("My Tickets"));

        String[] cols = {"ID", "Title", "Description", "Status"};

        model = new DefaultTableModel(cols, 0) {
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };

        table = new JTable(model);
        UITheme.styleTable(table);

        panel.add(new JScrollPane(table), BorderLayout.CENTER);

        // Buttons
        JPanel btnPanel = new JPanel();

        JButton refresh = new JButton("Refresh");
        UITheme.styleButton(refresh);
        refresh.addActionListener(e -> loadTickets());

        JButton delete = new JButton("Delete");
        UITheme.styleDangerButton(delete);
        delete.addActionListener(e -> deleteTicket());

        btnPanel.add(refresh);
        btnPanel.add(delete);

        panel.add(btnPanel, BorderLayout.SOUTH);

        loadTickets();

        return panel;
    }

    /**
     * Create ticket logic
     */
    private void createTicket() {

        String title = titleField.getText().trim();
        String desc = descField.getText().trim();

        if (title.isEmpty() || desc.isEmpty()) {
            showWarning("Please fill all fields");
            return;
        }

        try {
            TicketService.createTicket(title, desc, username);

            showInfo("Ticket created");
            clearFields();
            loadTickets();

        } catch (Exception e) {
            showError(e.getMessage());
        }
    }

    /**
     * Load tickets into table
     */
    private void loadTickets() {

        model.setRowCount(0);

        try {
            List<Ticket> list = TicketService.getTickets();

            for (Ticket t : list) {
                if (username.equals(t.getUser())) {
                    model.addRow(new Object[]{
                            t.getId(),
                            t.getTitle(),
                            shorten(t.getDescription()),
                            t.getStatus()
                    });
                }
            }

            statusLabel.setText("Loaded " + model.getRowCount() + " tickets");

        } catch (Exception e) {
            showError("Failed to load tickets");
        }
    }

    /**
     * Delete selected ticket
     */
    private void deleteTicket() {

        int row = table.getSelectedRow();
        if (row == -1) {
            showWarning("Select a ticket first");
            return;
        }

        String id = model.getValueAt(row, 0).toString();

        if (JOptionPane.showConfirmDialog(this,
                "Delete ticket " + id + "?") == JOptionPane.YES_OPTION) {

            try {
                TicketService.deleteTicket(id, username);
                model.removeRow(row);
                showInfo("Deleted ticket " + id);

            } catch (Exception e) {
                showError(e.getMessage());
            }
        }
    }

    /**
     * Utility methods
     */
    private void clearFields() {
        titleField.setText("");
        descField.setText("");
    }

    private String shorten(String text) {
        return text.length() > 30 ? text.substring(0, 30) + "..." : text;
    }

    private void showWarning(String msg) {
        JOptionPane.showMessageDialog(this, msg);
    }

    private void showError(String msg) {
        JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE);
    }

    private void showInfo(String msg) {
        JOptionPane.showMessageDialog(this, msg, "Success", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * GridBag helpers (reduces messy layout code)
     */
    private GridBagConstraints baseGBC() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0;
        gbc.gridy = 0;
        return gbc;
    }

    private GridBagConstraints nextRow(GridBagConstraints gbc) {
        gbc.gridy++;
        return gbc;
    }
}