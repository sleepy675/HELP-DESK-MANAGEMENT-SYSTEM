package ui;

import javax.swing.*;
import service.AuthService;
import model.User;
import java.awt.*;

/**
 * Registration Screen
 * 
 * Allows new users to:
 * - Create account
 * - Choose role (user / support)
 * - Validate input
 * - Navigate back to login
 */
public class RegisterUI extends JFrame {

    public RegisterUI() {

        setTitle("Help Desk System - Register");
        setSize(400, 380);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setResizable(false);

        // Main container
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBackground(UITheme.BG_COLOR);

        // Header
        mainPanel.add(
                UITheme.createHeaderPanel("Create New Account"),
                BorderLayout.NORTH
        );

        // Form panel
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBackground(UITheme.BG_COLOR);
        formPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 5, 8, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1;

        // ===== Username =====
        JLabel userLabel = createLabel("Username:");
        gbc.gridy = 0;
        formPanel.add(userLabel, gbc);

        JTextField usernameField = new JTextField();
        UITheme.styleTextField(usernameField);
        gbc.gridy = 1;
        gbc.ipady = 8;
        formPanel.add(usernameField, gbc);
        gbc.ipady = 0;

        // ===== Password =====
        JLabel passLabel = createLabel("Password:");
        gbc.gridy = 2;
        formPanel.add(passLabel, gbc);

        JPasswordField passwordField = new JPasswordField();
        UITheme.stylePasswordField(passwordField);
        gbc.gridy = 3;
        gbc.ipady = 8;
        formPanel.add(passwordField, gbc);
        gbc.ipady = 0;

        // ===== Role Selection =====
        JLabel roleLabel = createLabel("Select Role:");
        gbc.gridy = 4;
        formPanel.add(roleLabel, gbc);

        JComboBox<String> roleBox = new JComboBox<>(new String[]{"user", "support"});
        UITheme.styleComboBox(roleBox);
        gbc.gridy = 5;
        gbc.ipady = 6;
        formPanel.add(roleBox, gbc);
        gbc.ipady = 0;

        // Info text
        JLabel infoLabel = new JLabel("(User = Create tickets, Support = Assist users)");
        infoLabel.setFont(new Font("Arial", Font.ITALIC, 10));
        infoLabel.setForeground(new Color(120, 120, 120));
        gbc.gridy = 6;
        formPanel.add(infoLabel, gbc);

        // Message label (error/success)
        JLabel messageLabel = new JLabel(" ");
        messageLabel.setFont(new Font("Arial", Font.PLAIN, 11));
        gbc.gridy = 7;
        formPanel.add(messageLabel, gbc);

        // ===== Buttons =====
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        buttonPanel.setBackground(UITheme.BG_COLOR);

        JButton registerBtn = createRegisterButton();
        JButton backBtn = createBackButton();

        buttonPanel.add(registerBtn);
        buttonPanel.add(backBtn);

        gbc.gridy = 8;
        gbc.insets = new Insets(20, 5, 8, 5);
        formPanel.add(buttonPanel, gbc);

        mainPanel.add(formPanel, BorderLayout.CENTER);

        // ===== Actions =====

        registerBtn.addActionListener(e -> {

            String username = usernameField.getText().trim();
            String password = new String(passwordField.getPassword());
            String role = roleBox.getSelectedItem().toString();

            // Validation
            if (username.isEmpty() || password.isEmpty()) {
                showMessage(messageLabel, "⚠ Please fill in all fields", UITheme.WARNING_COLOR);
                return;
            }

            if (username.length() < 3) {
                showMessage(messageLabel, "⚠ Username must be at least 3 characters", UITheme.WARNING_COLOR);
                return;
            }

            if (password.length() < 4) {
                showMessage(messageLabel, "⚠ Password must be at least 4 characters", UITheme.WARNING_COLOR);
                return;
            }

            try {
                User newUser = new User(username, password, role);
                AuthService.register(newUser);

                showMessage(messageLabel, "✓ Registration successful!", UITheme.SUCCESS_COLOR);
                registerBtn.setEnabled(false);

                // Auto-close after 2 seconds
                new Timer(2000, event -> dispose()).start();

            } catch (Exception ex) {
                showMessage(messageLabel,
                        "✗ Registration failed: " + ex.getMessage(),
                        UITheme.ERROR_COLOR);
            }
        });

        // Back button
        backBtn.addActionListener(e -> dispose());

        add(mainPanel);
        setVisible(true);
    }

    /**
     * Helper method to create styled labels
     */
    private JLabel createLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(UITheme.LABEL_FONT);
        label.setForeground(UITheme.TEXT_COLOR);
        return label;
    }

    /**
     * Show message in label with color
     */
    private void showMessage(JLabel label, String text, Color color) {
        label.setText(text);
        label.setForeground(color);
    }

    /**
     * Styled Register Button
     */
    private JButton createRegisterButton() {
        JButton btn = new JButton("Register");
        UITheme.styleSuccessButton(btn);
        return btn;
    }

    /**
     * Styled Back Button
     */
    private JButton createBackButton() {
        JButton btn = new JButton("Back");
        UITheme.styleButton(btn);
        return btn;
    }
}