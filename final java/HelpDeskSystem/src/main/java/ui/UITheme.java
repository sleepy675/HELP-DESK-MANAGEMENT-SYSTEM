package ui;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.JTableHeader;
import java.awt.*;

/**
 * UITheme
 * 
 * Central place for:
 * - Colors
 * - Fonts
 * - Component styling
 * 
 * This helps maintain a consistent UI across the application.
 */
public class UITheme {

    // ================= COLORS =================

    public static final Color PRIMARY_COLOR   = new Color(41, 128, 185);
    public static final Color SECONDARY_COLOR = new Color(52, 73, 94);
    public static final Color SUCCESS_COLOR   = new Color(39, 174, 96);
    public static final Color ERROR_COLOR     = new Color(231, 76, 60);

    public static final Color BG_COLOR     = new Color(236, 240, 241);
    public static final Color TEXT_COLOR   = new Color(44, 62, 80);
    public static final Color BORDER_COLOR = new Color(189, 195, 199);
    public static final Color WARNING_COLOR = new Color(241, 196, 15);

    // ================= FONTS =================

    public static final Font TITLE_FONT        = new Font("Segoe UI", Font.BOLD, 24);
    public static final Font HEADER_FONT       = new Font("Segoe UI", Font.BOLD, 14);
    public static final Font LABEL_FONT        = new Font("Segoe UI", Font.PLAIN, 12);
    public static final Font TABLE_HEADER_FONT = new Font("Segoe UI", Font.BOLD, 12);
    public static final Font BUTTON_FONT       = new Font("Segoe UI", Font.BOLD, 12);
    public static final Font STATS_FONT        = new Font("Segoe UI", Font.BOLD, 16);

    // ================= SIZES =================

    public static final int BUTTON_WIDTH  = 120;
    public static final int BUTTON_HEIGHT = 35;

    // ================= BUTTON STYLING =================

    public static void styleButton(JButton btn) {
        applyButtonStyle(btn, PRIMARY_COLOR, PRIMARY_COLOR.darker());
    }

    public static void styleSuccessButton(JButton btn) {
        applyButtonStyle(btn, SUCCESS_COLOR, SUCCESS_COLOR.darker());
    }

    public static void styleDangerButton(JButton btn) {
        applyButtonStyle(btn, ERROR_COLOR, ERROR_COLOR.darker());
    }

    /**
     * Base styling used by all buttons
     */
    private static void applyButtonStyle(JButton btn, Color baseColor, Color hoverColor) {

        btn.setFont(BUTTON_FONT);
        btn.setBackground(baseColor);
        btn.setForeground(Color.WHITE);
        btn.setFocusPainted(false);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));

        btn.setPreferredSize(new Dimension(BUTTON_WIDTH, BUTTON_HEIGHT));

        btn.setBorder(createBorder(hoverColor, 1));

        // Hover effect
        btn.addMouseListener(new java.awt.event.MouseAdapter() {

            public void mouseEntered(java.awt.event.MouseEvent e) {
                btn.setBackground(hoverColor);
                btn.setBorder(createBorder(hoverColor.darker(), 2));
            }

            public void mouseExited(java.awt.event.MouseEvent e) {
                btn.setBackground(baseColor);
                btn.setBorder(createBorder(hoverColor, 1));
            }
        });
    }

    /**
     * Helper method to create consistent borders
     */
    private static Border createBorder(Color color, int thickness) {
        return BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(color, thickness),
                BorderFactory.createEmptyBorder(8, 16, 8, 16)
        );
    }

    // ================= INPUT FIELDS =================

    public static void styleTextField(JTextField field) {

        field.setFont(LABEL_FONT);
        field.setBackground(Color.WHITE);
        field.setCaretColor(PRIMARY_COLOR);

        field.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_COLOR),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
    }

    public static void stylePasswordField(JPasswordField field) {
        styleTextField(field); // reuse same style
    }

    public static void styleComboBox(JComboBox<?> combo) {
        combo.setFont(LABEL_FONT);
        combo.setBackground(Color.WHITE);
        combo.setForeground(TEXT_COLOR);
    }

    // ================= PANELS =================

    /**
     * Creates a standard header panel used across screens
     */
    public static JPanel createHeaderPanel(String title) {

        JPanel panel = new JPanel();
        panel.setBackground(PRIMARY_COLOR);
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JLabel label = new JLabel(title);
        label.setFont(HEADER_FONT);
        label.setForeground(Color.WHITE);

        panel.add(label);
        return panel;
    }

    // ================= TABLE =================

    public static void styleTable(JTable table) {

        table.setRowHeight(28);
        table.setFont(LABEL_FONT);
        table.setGridColor(BORDER_COLOR);

        JTableHeader header = table.getTableHeader();
        header.setFont(TABLE_HEADER_FONT);
        header.setBackground(SECONDARY_COLOR);
        header.setForeground(Color.WHITE);
    }
}