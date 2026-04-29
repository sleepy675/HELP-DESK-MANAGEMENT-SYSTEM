package ui;

import javax.swing.*;
import service.AuthService;
import model.User;
import java.awt.*;

/**
 * Login Screen for Help Desk System
 * 
 * Features:
 * - User login with username & password
 * - Error handling
 * - Navigation to Register screen
 * - Role-based redirection after login
 */
public class LoginUI extends JFrame {

    public LoginUI() {

        setTitle("Help Desk System - Login");
        setSize(400, 320);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setResizable(false);

        // Main container
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBackground(UITheme.BG_COLOR);

        // Header section
        mainPanel.add(
                UITheme.createHeaderPanel("Login to Help Desk System"),
                BorderLayout.NORTH
        );

        // Center content (form)
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBackground(UITheme.BG_COLOR);
        formPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 5, 8, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1;

        // ===== Username =====
        JLabel userLabel = createLabel("Username:");
        gbc.gridx = 0;
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

        // ===== Error message =====
        JLabel errorLabel = new JLabel(" ");
        errorLabel.setFont(new Font("Arial", Font.PLAIN, 11));
        errorLabel.setForeground(UITheme.ERROR_COLOR);
        gbc.gridy = 4;
        formPanel.add(errorLabel, gbc);

        // ===== Buttons =====
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        buttonPanel.setBackground(UITheme.BG_COLOR);

        JButton loginBtn = createLoginButton();
        JButton registerBtn = createRegisterButton();

        buttonPanel.add(loginBtn);
        buttonPanel.add(registerBtn);

        gbc.gridy = 5;
        gbc.insets = new Insets(20, 5, 8, 5);
        formPanel.add(buttonPanel, gbc);

        mainPanel.add(formPanel, BorderLayout.CENTER);

        // ===== Actions =====

        // Login button logic
        loginBtn.addActionListener(e -> {

            String username = usernameField.getText().trim();
            String password = new String(passwordField.getPassword());

            // Basic validation
            if (username.isEmpty() || password.isEmpty()) {
                errorLabel.setText("⚠ Please fill in all fields");
                return;
            }

            try {
                User user = AuthService.login(username, password);

                if (user != null) {

                    // Redirect based on role
                    switch (user.getRole()) {
                        case "admin":
                            new AdminDashboard();
                            break;
                        case "user":
                            new UserDashboard(user.getUsername());
                            break;
                        case "support":
                            new SupportDashboard(user.getUsername());
                            break;
                    }

                    dispose(); // close login screen

                } else {
                    errorLabel.setText("✗ Invalid username or password");
                    passwordField.setText("");
                }

            } catch (Exception ex) {
                errorLabel.setText("✗ Login failed: " + ex.getMessage());
            }
        });

        // Register button logic
        registerBtn.addActionListener(e -> {
            new RegisterUI();
            dispose();
        });

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
     * Styled Login Button
     */
    private JButton createLoginButton() {
        JButton btn = new JButton("Login");
        UITheme.styleButton(btn);
        return btn;
    }

    /**
     * Styled Register Button with hover effect
     */
    private JButton createRegisterButton() {

        JButton btn = new JButton("Register");

        btn.setFont(UITheme.BUTTON_FONT);
        btn.setBackground(UITheme.SUCCESS_COLOR);
        btn.setForeground(Color.RED);
        btn.setFocusPainted(false);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));

        // Border styling
        btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(30, 150, 80), 1),
                BorderFactory.createEmptyBorder(8, 16, 8, 16)
        ));

        btn.setPreferredSize(
                new Dimension(UITheme.BUTTON_WIDTH, UITheme.BUTTON_HEIGHT)
        );

        // Hover effect
        btn.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btn.setBackground(new Color(30, 150, 80));
            }

            public void mouseExited(java.awt.event.MouseEvent evt) {
                btn.setBackground(UITheme.SUCCESS_COLOR);
            }
        });

        return btn;
    }
}