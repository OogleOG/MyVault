package vault.backup;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.extras.FlatSVGIcon;
import com.formdev.flatlaf.extras.components.FlatTextField;
import com.formdev.flatlaf.util.SystemInfo;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.Timer;
import javax.swing.border.EmptyBorder;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.time.Instant;
import java.util.*;
import java.util.List;
import java.util.prefs.Preferences;

public class PasswordVaultFXBackup {

    // ===== Vault file path =====
    //private static final Path VAULT_DIR = Paths.get(System.getProperty("user.home"), ".vault");
    //private static final Path VAULT_PATH = VAULT_DIR.resolve("vault.dat");

    // Preferences (theme etc)
    private final Preferences prefs = Preferences.userNodeForPackage(PasswordVaultFXBackup.class);
    private static final String PREF_DARK = "darkTheme";
    private static final String PREF_VAULT_DIR = "vaultDir";

    // Dynamic vault path (was static constants)
    private Path getVaultDir() {
        String p = prefs.get(PREF_VAULT_DIR, null);
        if (p != null && !p.isBlank()) return Paths.get(p);
        return Paths.get(System.getProperty("user.home"), ".vault");
    }
    private Path getVaultPath() {
        return getVaultDir().resolve("vault.dat");
    }


    // ===== Binary format header =====
    private static final byte[] MAGIC = new byte[]{'J','V','L','T'};
    private static final byte VERSION = 1;

    // ===== Crypto params =====
    private static final int SALT_LEN = 16;     // 128-bit
    private static final int IV_LEN = 12;       // 96-bit for GCM
    private static final int KEY_LEN_BITS = 256;// AES-256
    private static final int PBKDF2_ITERS = 600_000;
    private static final String KDF_ALGO = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_ALGO = "AES/GCM/NoPadding";

    private static final SecureRandom RNG = new SecureRandom();
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    // ===== Data models =====
    public static class Entry {
        String id;
        String label;
        String username;
        String email;
        String password; // kept in-memory; encrypted on disk
        long createdAt;
        long updatedAt;
        String category;
    }
    public static class VaultData {
        String vaultName;
        List<Entry> entries = new ArrayList<>();
        long lastModified;
    }

    // ===== App state =====
    private JFrame frame;
    private JTable table;
    private DefaultTableModel tableModel;
    private TableRowSorter<TableModel> sorter;
    private FlatTextField searchField;
    private DefaultListModel<String> categoryModel;
    private JList<String> categoryList;
    private char[] masterPassword; // only held while unlocked
    private VaultData data;         // decrypted while unlocked
    private JLabel statusLabel;
    private JPanel emptyState;

    // Idle auto-lock
    private long lastInteraction = System.currentTimeMillis();
    private static final long IDLE_LOCK_MS = 5 * 60 * 1000; // 5 minutes
    private Timer idleTimer;


    public static void main(String[] args) {
        // Theme bootstrap
        boolean dark = Preferences.userNodeForPackage(PasswordVaultFXBackup.class)
                .getBoolean(PREF_DARK, true);

        SwingUtilities.invokeLater(() -> {
            try {
                if (dark) FlatDarkLaf.setup(); else FlatLightLaf.setup();
                if (SystemInfo.isMacOS) System.setProperty("apple.laf.useScreenMenuBar", "true");

                // ---- FlatLaf density / style tweaks (apply BEFORE building UI) ----
                UIManager.put("Component.arrowType", "chevron");   // nicer combo arrows
                UIManager.put("Component.innerFocusWidth", 0);      // tighter focus ring
                UIManager.put("Component.minimumWidth", 0);         // let buttons be compact
                // (Optional) rounder corners if you like:
                // UIManager.put("Component.arc", 12);

            } catch (Exception ignore) {}

            new PasswordVaultFXBackup().start();
        });
    }


    void start() {
        try {
            Files.createDirectories(getVaultDir());
        } catch (IOException e) {
            showError("Cannot create vault folder: " + e.getMessage());
            return;
        }
        showUnlockOrInit();
    }

    private void showUnlockOrInit() {
        if (Files.exists(getVaultPath())) {
            unlockExistingVault();
        } else {
            initNewVault();
        }
    }

    private void unlockExistingVault() {
        JPasswordField pf = new JPasswordField();
        pf.putClientProperty("JPasswordField.showRevealButton", true);
        int res = JOptionPane.showConfirmDialog(null, pf, "Enter Master Password", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return; // exit silently
        char[] mpw = pf.getPassword();
        try {
            VaultData vd = loadVault(getVaultPath(), mpw);
            if (vd == null) {
                Arrays.fill(mpw, '\0');
                showError("Incorrect password or vault corrupted.");
                unlockExistingVault();
                return;
            }
            this.masterPassword = mpw;
            this.data = vd;
            buildMainUI();
        } catch (Exception ex) {
            Arrays.fill(mpw, '\0');
            showError("Failed to open vault: " + ex.getMessage());
        }
    }

    private void initNewVault() {
        JPanel panel = new JPanel(new GridLayout(0,1,8,8));
        JPasswordField p1 = new JPasswordField();
        p1.putClientProperty("JPasswordField.showRevealButton", true);
        JPasswordField p2 = new JPasswordField();
        p2.putClientProperty("JPasswordField.showRevealButton", true);
        JTextField name = new JTextField("MyVault");
        panel.add(new JLabel("Vault Name:"));
        panel.add(name);
        panel.add(new JLabel("Create Master Password:"));
        panel.add(p1);
        panel.add(new JLabel("Confirm Master Password:"));
        panel.add(p2);
        int res = JOptionPane.showConfirmDialog(null, panel, "Initialize Vault", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;
        if (!Arrays.equals(p1.getPassword(), p2.getPassword())) {
            showError("Passwords do not match.");
            initNewVault();
            return;
        }
        char[] mpw = p1.getPassword();
        try {
            VaultData vd = new VaultData();
            vd.vaultName = name.getText().isBlank() ? "MyVault" : name.getText().trim();
            vd.lastModified = System.currentTimeMillis();
            saveVault(getVaultPath(), vd, mpw);
            this.masterPassword = mpw;
            this.data = vd;
            buildMainUI();
        } catch (Exception ex) {
            Arrays.fill(mpw, '\0');
            showError("Failed to create vault: " + ex.getMessage());
        }
    }

    private void buildMainUI() {
        frame = new JFrame(data.vaultName + " — Password Vault");
        frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        frame.setSize(980, 600);
        frame.setLocationRelativeTo(null);

        try {
            List<Image> icons = new ArrayList<>();
            icons.add(new ImageIcon(getClass().getResource("/icons/app-icon-16.png")).getImage());
            icons.add(new ImageIcon(getClass().getResource("/icons/app-icon-32.png")).getImage());
            icons.add(new ImageIcon(getClass().getResource("/icons/app-icon-128.png")).getImage());
            icons.add(new ImageIcon(getClass().getResource("/icons/app-icon-256.png")).getImage());
            frame.setIconImages(icons);
        } catch (Exception e) {
            System.err.println("Could not load app icons: " + e.getMessage());
        }


        JPanel root = new JPanel(new BorderLayout(10,10));
        root.setBorder(new EmptyBorder(12,12,12,12));

        // === Menu bar ===
        JMenuBar mb = new JMenuBar();
        JMenu fileMenu = new JMenu("File");
        JMenu settingsMenu = new JMenu("Settings");
        JMenu helpMenu = new JMenu("Help");

        JMenuItem changeLoc = new JMenuItem("Change Vault Location…");
        changeLoc.addActionListener(e -> onChangeVaultLocation());

        JMenuItem lockItem = new JMenuItem("Lock");
        lockItem.addActionListener(e -> lockAndReturnToUnlock());

        JMenuItem exitItem = new JMenuItem("Exit");
        exitItem.addActionListener(e -> { if (frame != null) frame.dispose(); });

        settingsMenu.add(changeLoc);
        fileMenu.add(lockItem);
        fileMenu.addSeparator();
        fileMenu.add(exitItem);
        mb.add(fileMenu);
        mb.add(settingsMenu);
        mb.add(helpMenu);
        frame.setJMenuBar(mb);

        JMenuItem helpQuickStart = new JMenuItem("Quick Start");
        helpQuickStart.addActionListener(e -> showQuickStart());

        JMenuItem helpVaultSync = new JMenuItem("Vault Location & Sync");
        helpVaultSync.addActionListener(e -> showVaultAndSyncHelp());

        JMenuItem helpShortcuts = new JMenuItem("Keyboard Shortcuts");
        helpShortcuts.addActionListener(e -> showShortcuts());

        JMenuItem helpSecurity = new JMenuItem("Security Notes");
        helpSecurity.addActionListener(e -> showSecurityNotes());

        JMenuItem helpOpenFolder = new JMenuItem("Open Vault Folder");
        helpOpenFolder.addActionListener(e -> openVaultFolder());

        JMenuItem helpAbout = new JMenuItem("About");
        helpAbout.addActionListener(e -> showAbout());

// add to the Help menu
        helpMenu.add(helpQuickStart);
        helpMenu.add(helpVaultSync);
        helpMenu.add(helpShortcuts);
        helpMenu.add(helpSecurity);
        helpMenu.addSeparator();
        helpMenu.add(helpOpenFolder);
        helpMenu.addSeparator();
        helpMenu.add(helpAbout);

        // === Toolbar ===
        JToolBar tb = new JToolBar();
        tb.setFloatable(false);
        JButton addBtn = makeToolButton("icons/add.svg", "Add");
        JButton editBtn = makeToolButton("icons/edit.svg", "Edit");
        JButton delBtn = makeToolButton("icons/delete.svg", "Delete");
        JButton copyUserBtn = makeToolButton("icons/copy.svg", "Copy User");
        JButton copyEmailBtn = makeToolButton("icons/copy.svg", "Copy Email");
        JButton copyPassBtn = makeToolButton("icons/key.svg", "Copy Password");
        JButton lockBtn = makeToolButton("icons/lock.svg", "Lock");

        JToggleButton themeToggle = new JToggleButton(new FlatSVGIcon("icons/dark.svg"));
        themeToggle.setSelected(prefs.getBoolean(PREF_DARK, true));
        themeToggle.setToolTipText("Toggle Light/Dark Theme");

        tb.add(addBtn); tb.add(editBtn); tb.add(delBtn);
        tb.addSeparator();
        tb.add(copyUserBtn); tb.add(copyEmailBtn); tb.add(copyPassBtn);
        tb.addSeparator();
        tb.add(lockBtn);
        tb.add(Box.createHorizontalGlue());
        tb.add(themeToggle);

        // === Categories sidebar ===
        categoryModel = new DefaultListModel<>();
        categoryList = new JList<>(categoryModel);
        categoryList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        categoryList.setFixedCellHeight(24);
        categoryList.setBorder(new EmptyBorder(8, 8, 8, 8));

        JScrollPane catScroll = new JScrollPane(categoryList);
        catScroll.setPreferredSize(new Dimension(200, 0)); // ~200px wide sidebar

        root.add(catScroll, BorderLayout.WEST);


        // === Search field ===
        searchField = new FlatTextField();
        searchField.setPlaceholderText("Search label, username, or email…");
        searchField.putClientProperty("JComponent.roundRect", true);
        searchField.setColumns(28);

        JPanel north = new JPanel(new BorderLayout(8,8));
        north.add(tb, BorderLayout.NORTH);
        north.add(searchField, BorderLayout.SOUTH);

        root.add(north, BorderLayout.NORTH);

        // === Table ===
        tableModel = new DefaultTableModel(new Object[]{"Category","Label","Username","Email","Updated","ID"},0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        sorter = new TableRowSorter<>(table.getModel());
        table.setRowSorter(sorter);

        // Improve table look
        table.setFillsViewportHeight(true);
        table.setRowHeight(24);
        table.putClientProperty("JTable.showHorizontalLines", false);
        table.putClientProperty("JTable.showVerticalLines", false);
        table.putClientProperty("JTable.alternateRowColor", true);

        resizeColumns();
        refreshTable();
        rebuildCategories();
        applyFilters();

        root.add(new JScrollPane(table), BorderLayout.CENTER);

        emptyState = new JPanel(new BorderLayout());
        emptyState.add(new JLabel("<html><center><h2>No entries yet</h2><div>Click <b>Add</b> to create your first item.</div></center></html>", SwingConstants.CENTER), BorderLayout.CENTER);

        JComponent center = data.entries.isEmpty() ? emptyState : new JScrollPane(table);
        root.add(center, BorderLayout.CENTER);

        // === Status bar ===
        statusLabel = new JLabel("Unlocked — entries: " + data.entries.size());
        JPanel status = new JPanel(new BorderLayout());
        status.setBorder(new EmptyBorder(4,0,0,0));
        status.add(statusLabel, BorderLayout.WEST);
        root.add(status, BorderLayout.SOUTH);

        JPopupMenu rowMenu = createRowMenu();
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mousePressed(java.awt.event.MouseEvent e) { maybeShow(e); }
            @Override public void mouseReleased(java.awt.event.MouseEvent e) { maybeShow(e); }
            private void maybeShow(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0) table.setRowSelectionInterval(row, row);
                    rowMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        // === Wire actions ===
        addBtn.addActionListener(e -> onAdd());
        editBtn.addActionListener(e -> onEdit());
        delBtn.addActionListener(e -> onDelete());
        copyUserBtn.addActionListener(e -> copySelected("username"));
        copyEmailBtn.addActionListener(e -> copySelected("email"));
        copyPassBtn.addActionListener(e -> copySelected("password"));
        lockBtn.addActionListener(e -> lockAndReturnToUnlock());

        // in buildMainUI() after creating buttons:
        addBtn.setMnemonic('A'); editBtn.setMnemonic('E'); delBtn.setMnemonic('D');
        searchField.getInputMap().put(KeyStroke.getKeyStroke("control F"), "focusSearch");
        searchField.getActionMap().put("focusSearch", new AbstractAction(){ public void actionPerformed(java.awt.event.ActionEvent e){ searchField.requestFocusInWindow(); }});
        table.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke("DELETE"), "deleteRow");
        table.getActionMap().put("deleteRow", new AbstractAction(){ public void actionPerformed(java.awt.event.ActionEvent e){ onDelete(); }});


        themeToggle.addActionListener(e -> {
            boolean dark = themeToggle.isSelected();
            prefs.putBoolean(PREF_DARK, dark);
            try {
                if (dark) FlatDarkLaf.setup(); else FlatLightLaf.setup();
                SwingUtilities.updateComponentTreeUI(frame);
            } catch (Exception ex) {
                showError("Failed to switch theme: " + ex.getMessage());
            }
        });

        // Search
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            void update() {
                applyFilters();
                statusLabel.setText("Unlocked — entries: " + data.entries.size());
            }
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { update(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { update(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { update(); }
        });


        // Idle lock
        Toolkit.getDefaultToolkit().addAWTEventListener(ev -> lastInteraction = System.currentTimeMillis(),
                AWTEvent.KEY_EVENT_MASK | AWTEvent.MOUSE_EVENT_MASK | AWTEvent.MOUSE_MOTION_EVENT_MASK);
        idleTimer = new Timer(5_000, e -> {
            if (System.currentTimeMillis() - lastInteraction > IDLE_LOCK_MS) {
                idleTimer.stop();
                lockAndReturnToUnlock();
            }
        });
        idleTimer.start();

        JLabel creditsLabel = new JLabel("Built by Oogle ❤️");
        creditsLabel.setFont(creditsLabel.getFont().deriveFont(Font.ITALIC, 11f));
// Theme-aware subtle color
        Color subtle = UIManager.getColor("Label.disabledForeground");
        if (subtle != null) creditsLabel.setForeground(subtle);

        status.setBorder(new EmptyBorder(4, 0, 0, 0));
        status.add(statusLabel, BorderLayout.WEST); // left side
        status.add(creditsLabel, BorderLayout.EAST); // right side

        root.add(status, BorderLayout.SOUTH);

        String b = prefs.get("winBounds", null);
        if (b != null) {
            String[] p = b.split(",");
            frame.setBounds(Integer.parseInt(p[0]), Integer.parseInt(p[1]), Integer.parseInt(p[2]), Integer.parseInt(p[3]));
        }
        frame.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override public void componentMoved(java.awt.event.ComponentEvent e){ save(); }
            @Override public void componentResized(java.awt.event.ComponentEvent e){ save(); }
            private void save(){ Rectangle r = frame.getBounds(); prefs.put("winBounds", r.x+","+r.y+","+r.width+","+r.height); }
        });

        frame.setContentPane(root);
        frame.setVisible(true);
    }

    private void updateCenterView(JPanel root) {
        BorderLayout bl = (BorderLayout) root.getLayout();
        Component current = bl.getLayoutComponent(BorderLayout.CENTER);
        if (current != null) root.remove(current);
        root.add(data.entries.isEmpty() ? emptyState : new JScrollPane(table), BorderLayout.CENTER);
        root.revalidate(); root.repaint();
    }

    private JPopupMenu createRowMenu() {
        JPopupMenu m = new JPopupMenu();
        JMenuItem edit = new JMenuItem("Edit");     edit.addActionListener(e -> onEdit());
        JMenuItem copyU= new JMenuItem("Copy User");copyU.addActionListener(e -> copySelected("username"));
        JMenuItem copyE= new JMenuItem("Copy Email");copyE.addActionListener(e -> copySelected("email"));
        JMenuItem copyP= new JMenuItem("Copy Password");copyP.addActionListener(e -> copySelected("password"));
        JMenuItem del  = new JMenuItem("Delete");   del.addActionListener(e -> onDelete());
        m.add(edit); m.addSeparator(); m.add(copyU); m.add(copyE); m.add(copyP); m.addSeparator(); m.add(del);
        return m;
    }

    private void toast(String text) {
        JWindow w = new JWindow(frame);
        JLabel l = new JLabel("  " + text + "  ");
        l.setOpaque(true);
        l.setBackground(new Color(0,0,0,170));
        l.setForeground(Color.WHITE);
        w.add(l);
        w.pack();
        Point p = frame.getLocationOnScreen();
        w.setLocation(p.x + frame.getWidth() - w.getWidth() - 20, p.y + frame.getHeight() - w.getHeight() - 50);
        w.setAlwaysOnTop(true);
        w.setVisible(true);
        new javax.swing.Timer(1500, e -> w.dispose()) {{ setRepeats(false); }}.start();
    }

    private JButton makeToolButton(String iconPath, String tooltip) {
        JButton b = new JButton(new FlatSVGIcon(iconPath, 16, 16));
        b.setToolTipText(tooltip);
        b.putClientProperty("JButton.buttonType", "toolBarButton");
        return b;
    }

    private void resizeColumns() {
        TableColumnModel cols = table.getColumnModel();
        if (cols.getColumnCount() < 5) return;
        cols.getColumn(0).setPreferredWidth(260); // Label
        cols.getColumn(1).setPreferredWidth(180); // Username
        cols.getColumn(2).setPreferredWidth(220); // Email
        cols.getColumn(3).setPreferredWidth(140); // Updated
        cols.getColumn(4).setPreferredWidth(80);  // ID
    }

    void refreshTable() {
        tableModel.setRowCount(0);
        for (Entry e : data.entries) {
            tableModel.addRow(new Object[]{
                    ns(e.category),                  // col 0
                    e.label,                         // col 1
                    ns(e.username),                  // col 2
                    ns(e.email),                     // col 3
                    Instant.ofEpochMilli(e.updatedAt), // col 4
                    e.id                             // col 5
            });
        }
    }

    private String ns(String s) { return (s == null || s.isEmpty()) ? "-" : s; }

    private Entry getSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return null;
        int modelRow = table.convertRowIndexToModel(viewRow);
        String id = (String) tableModel.getValueAt(modelRow, 4);
        for (Entry e : data.entries) if (e.id.equals(id)) return e;
        return null;
    }

    private void onAdd() {
        EntryForm form = new EntryForm(frame, null);
        Entry created = form.showDialog();
        if (created != null) {
            created.id = UUID.randomUUID().toString();
            long now = System.currentTimeMillis();
            created.createdAt = now; created.updatedAt = now;
            data.entries.add(created);
            persistAndRefresh();
        }
    }

    private void onEdit() {
        Entry sel = getSelected();
        if (sel == null) { showInfo("Select a row first."); return; }
        EntryForm form = new EntryForm(frame, sel);
        Entry edited = form.showDialog();
        if (edited != null) {
            sel.label = edited.label;
            sel.username = edited.username;
            sel.email = edited.email;
            if (edited.password != null) sel.password = edited.password; // may remain unchanged
            sel.updatedAt = System.currentTimeMillis();
            persistAndRefresh();
        }
    }

    private void onDelete() {
        Entry sel = getSelected();
        if (sel == null) { showInfo("Select a row first."); return; }
        int res = JOptionPane.showConfirmDialog(frame, "Delete '" + sel.label + "'?", "Confirm", JOptionPane.OK_CANCEL_OPTION);
        if (res == JOptionPane.OK_OPTION) {
            data.entries.remove(sel);
            persistAndRefresh();
        }
    }

    private void onChangeVaultLocation() {
        JFileChooser fc = new JFileChooser(getVaultDir().toFile());
        fc.setDialogTitle("Select a folder for your vault");
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        fc.setAcceptAllFileFilterUsed(false);
        int res = fc.showOpenDialog(frame);
        if (res != JFileChooser.APPROVE_OPTION) return;

        Path newDir = fc.getSelectedFile().toPath();
        try {
            Files.createDirectories(newDir);
            Path newVault = newDir.resolve("vault.dat");
            Path oldVault = getVaultPath();

            if (Files.exists(newVault)) {
                // Adopting an existing vault at the new location
                int c = JOptionPane.showConfirmDialog(frame,
                        "A vault already exists here.\nUse that one instead?",
                        "Existing Vault Found",
                        JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
                if (c != JOptionPane.OK_OPTION) return;
                // Just switch preference; do not overwrite
                prefs.put(PREF_VAULT_DIR, newDir.toAbsolutePath().toString());
                showInfo("Vault location updated. Please unlock again.");
                lockAndReturnToUnlock();
                return;
            }

            // No vault there: migrate current (if we’re unlocked)
            if (data != null && masterPassword != null) {
                // Re-save to new location to ensure format integrity
                saveVault(newVault, data, masterPassword);
            } else if (Files.exists(oldVault)) {
                // We’re on the unlock screen: move/copy the file
                try {
                    Files.move(oldVault, newVault, StandardCopyOption.ATOMIC_MOVE);
                } catch (Exception moveFail) {
                    // Fallback to copy if cross-device
                    Files.copy(oldVault, newVault, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
                    // Optional: keep old as backup rather than deleting
                }
            } else {
                // No existing vault; create empty one with a quick init flow
                showInfo("No existing vault to migrate. The app will create one here when you initialize.");
            }

            prefs.put(PREF_VAULT_DIR, newDir.toAbsolutePath().toString());
            showInfo("Vault location updated. Please unlock again.");
            lockAndReturnToUnlock();

        } catch (Exception ex) {
            showError("Failed to change location: " + ex.getMessage());
        }
    }


    private void copySelected(String field) {
        Entry sel = getSelected();
        if (sel == null) { showInfo("Select a row first."); return; }
        String text = switch (field) {
            case "username" -> sel.username;
            case "email" -> sel.email;
            case "password" -> sel.password;
            default -> null;
        };
        if (text == null || text.isEmpty()) { showInfo("Nothing to copy."); return; }
        copyToClipboardEphemeral(text, 15_000);
        showInfo("Copied " + field + " (clears in ~15s)");
    }

    private void copyToClipboardEphemeral(String s, int clearAfterMs) {
        Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
        cb.setContents(new StringSelection(s), null);
        new Timer(clearAfterMs, e -> {
            Clipboard cb2 = Toolkit.getDefaultToolkit().getSystemClipboard();
            cb2.setContents(new StringSelection(""), null);
        }) {{ setRepeats(false); }}.start();
    }

    private void persistAndRefresh() {
        try {
            data.lastModified = System.currentTimeMillis();
            saveVault(getVaultPath(), data, masterPassword);
            refreshTable();
            rebuildCategories();
            applyFilters();
            statusLabel.setText("Unlocked — entries: " + data.entries.size());
        } catch (Exception ex) {
            showError("Failed to save: " + ex.getMessage());
        }
    }

    private void lockAndReturnToUnlock() {
        if (frame != null) frame.dispose();
        if (idleTimer != null) idleTimer.stop();
        if (masterPassword != null) Arrays.fill(masterPassword, '\0');
        masterPassword = null;
        data = null;
        showInfo("Vault locked.");
        showUnlockOrInit();
    }

    // ======== Vault IO & Crypto ========

    private static void saveVault(Path p, VaultData data, char[] masterPassword) throws Exception {
        byte[] salt = new byte[SALT_LEN]; RNG.nextBytes(salt);
        SecretKey key = deriveKey(masterPassword, salt);
        byte[] iv = new byte[IV_LEN]; RNG.nextBytes(iv);
        byte[] plaintext = GSON.toJson(data).getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = encryptGCM(key, iv, plaintext);

        Path tmp = p.resolveSibling(p.getFileName().toString() + ".tmp");
        try (DataOutputStream out = new DataOutputStream(Files.newOutputStream(tmp, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))) {
            out.write(MAGIC);
            out.writeByte(VERSION);
            out.writeByte(SALT_LEN); out.write(salt);
            out.writeByte(IV_LEN);   out.write(iv);
            out.write(ciphertext);
        }
        Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        Arrays.fill(plaintext, (byte)0);
    }

    private static VaultData loadVault(Path p, char[] masterPassword) throws Exception {
        byte[] all = Files.readAllBytes(p);
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(all))) {
            byte[] magic = new byte[4]; in.readFully(magic);
            if (!Arrays.equals(magic, MAGIC)) return null;
            byte ver = in.readByte(); if (ver != VERSION) return null;
            int saltLen = in.readUnsignedByte(); byte[] salt = in.readNBytes(saltLen);
            int ivLen = in.readUnsignedByte();   byte[] iv   = in.readNBytes(ivLen);
            byte[] ciphertext = in.readAllBytes();
            SecretKey key = deriveKey(masterPassword, salt);
            byte[] plaintext = decryptGCM(key, iv, ciphertext);
            String json = new String(plaintext, StandardCharsets.UTF_8);
            Arrays.fill(plaintext, (byte)0);
            return GSON.fromJson(json, VaultData.class);
        }
    }

    private static SecretKey deriveKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERS, KEY_LEN_BITS);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(KDF_ALGO);
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] encryptGCM(SecretKey key, byte[] iv, byte[] plaintext) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(plaintext);
    }

    private static byte[] decryptGCM(SecretKey key, byte[] iv, byte[] ciphertext) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(ciphertext);
    }

    // ======== UI helpers ========
    private void showError(String msg) { JOptionPane.showMessageDialog(null, msg, "Error", JOptionPane.ERROR_MESSAGE); }
    private void showInfo(String msg) { JOptionPane.showMessageDialog(null, msg, "Info", JOptionPane.INFORMATION_MESSAGE); }

    // ======== Entry form dialog ========
    private static class EntryForm {
        private final JComboBox<String> category = new JComboBox<>();
        private final JDialog dialog;
        private final JTextField label = new JTextField();
        private final JTextField username = new JTextField();
        private final JTextField email = new JTextField();
        private final JPasswordField password = new JPasswordField();
        private Entry result;

        EntryForm(Frame owner, Entry existing) {
            dialog = new JDialog(owner, (existing == null ? "Add Entry" : "Edit Entry"), true);
            JPanel panel = new JPanel(new GridBagLayout());
            panel.setBorder(new EmptyBorder(14,14,14,14));
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(6,6,6,6);
            c.fill = GridBagConstraints.HORIZONTAL;
            c.gridx=0; c.gridy=0; panel.add(new JLabel("Label"), c);
            c.gridx=1; c.weightx=1; panel.add(label, c);
            c.weightx=0;
            c.gridx=0; c.gridy=1; panel.add(new JLabel("Username"), c);
            c.gridx=1; c.weightx=1; panel.add(username, c);
            c.weightx=0;
            c.gridx=0; c.gridy=2; panel.add(new JLabel("Email"), c);
            c.gridx=1; c.weightx=1; panel.add(email, c);
            c.weightx=0;
            c.gridx=0; c.gridy=3; panel.add(new JLabel("Password"), c);
            password.putClientProperty("JPasswordField.showRevealButton", true);
            c.gridx=1; c.weightx=1; panel.add(password, c);

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton ok = new JButton("Save"); JButton cancel = new JButton("Cancel");
            buttons.add(ok); buttons.add(cancel);

            ok.addActionListener(e -> {
                if (label.getText().trim().isEmpty()) {
                    JOptionPane.showMessageDialog(dialog, "Label required");
                    return;
                }
                Entry e1 = new Entry();
                e1.label = label.getText().trim();
                e1.username = username.getText().trim();
                e1.email = email.getText().trim();
                char[] pw = password.getPassword();
                if (existing == null) e1.password = new String(pw);
                else e1.password = (pw.length == 0) ? existing.password : new String(pw);
                Arrays.fill(pw, '\0');
                result = e1;
                dialog.dispose();
            });
            cancel.addActionListener(e -> { result = null; dialog.dispose(); });

            if (existing != null) {
                label.setText(existing.label);
                username.setText(existing.username);
                email.setText(existing.email);
                password.setText(""); // leave blank to keep existing
            }

            dialog.getContentPane().add(panel, BorderLayout.CENTER);
            dialog.getContentPane().add(buttons, BorderLayout.SOUTH);
            dialog.pack();
            dialog.setSize(460, dialog.getHeight());
            dialog.setLocationRelativeTo(owner);
        }

        Entry showDialog() {
            dialog.setVisible(true);
            return result;
        }
    }

    private void rebuildCategories() {
        if (categoryModel == null) return;
        java.util.Set<String> cats = new java.util.TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (Entry e : data.entries) {
            if (e.category != null && !e.category.isBlank()) cats.add(e.category.trim());
        }
        categoryModel.clear();
        categoryModel.addElement("All");
        categoryModel.addElement("Uncategorized");
        for (String c : cats) categoryModel.addElement(c);

        if (categoryList.getSelectedIndex() == -1) categoryList.setSelectedIndex(0);
    }

    private void applyFilters() {

    }


    private void showQuickStart() {
        String msg = """
        Welcome to Password Vault

        1) Create a master password (first launch) or unlock with it (later).
        2) Click Add to create entries (label, username/email, password).
        3) Search using the bar at the top; double-click an entry to edit.
        4) Copy username/email/password with the toolbar buttons (clipboard clears after ~15s).
        5) Use Settings → Change Vault Location… to move the vault to a folder of your choice (including a cloud-synced folder).

        Tip: Lock from File → Lock or via the toolbar. The app also auto-locks after a few minutes idle.
        """;
        JOptionPane.showMessageDialog(frame, msg, "Quick Start", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showVaultAndSyncHelp() {
        String path = getVaultPath().toAbsolutePath().toString();
        String dir  = getVaultDir().toAbsolutePath().toString();
        String msg = """
        Vault Location & Sync

        • Your data is a single encrypted file: vault.dat
        • Current folder:
          %s

        Sync options:
        • Put the file in a cloud-synced folder (OneDrive, Google Drive, Dropbox, Syncthing, etc.).
        • Use Settings → Change Vault Location… to move or adopt an existing vault.dat in another folder.

        Important:
        • Avoid editing from two machines at the same time; you could get 'conflicted copies'.
        • Best practice: unlock, make your changes, lock/close, give the sync client a moment to upload.

        You can open the vault folder from Help → Open Vault Folder.
        """.formatted(dir);
        JOptionPane.showMessageDialog(frame, msg, "Vault Location & Sync", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showShortcuts() {
        String msg = """
        Keyboard Shortcuts

        • Enter (on dialogs) .......... Confirm
        • Esc (on dialogs) ............ Cancel / Close
        • Ctrl+F / Cmd+F .............. Focus search
        • Delete (on table) ........... Delete selected entry
        • Ctrl+C on table cell ........ Copy cell text
        • Alt+F ........................ Open File menu
        • Alt+S ........................ Open Settings menu
        • Alt+H ........................ Open Help menu

        Tip: Use the search box to quickly filter by label, username or email.
        """;
        JOptionPane.showMessageDialog(frame, msg, "Keyboard Shortcuts", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showSecurityNotes() {
        String msg = """
        Security Notes

        • Encryption: AES-256-GCM; key from your master password (PBKDF2-HMAC-SHA256, 600k iterations).
        • The entire vault is encrypted; no plaintext is written to disk.
        • Clipboard clears automatically after ~15 seconds when copying secrets.
        • Java cannot guarantee zero copies in RAM; close/lock the app when not in use.
        • Back up 'vault.dat' safely (encrypted export coming soon). Never store your master password with it.
        • Changing the master password re-wraps the vault with the new key.

        For highest security, use a strong, unique master password and keep your operating system user account protected.
        """;
        JOptionPane.showMessageDialog(frame, msg, "Security Notes", JOptionPane.INFORMATION_MESSAGE);
    }

    private void openVaultFolder() {
        try {
            Path dir = getVaultDir();
            if (!Files.exists(dir)) Files.createDirectories(dir);
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().open(dir.toFile());
            } else {
                JOptionPane.showMessageDialog(frame,
                        "Vault folder:\n" + dir.toAbsolutePath(),
                        "Vault Folder", JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception ex) {
            showError("Could not open folder: " + ex.getMessage());
        }
    }

    private void showAbout() {
        String msg = """
        Password Vault
        Version: 1.x

        A local password manager with strong encryption and a clean UI.
        We make sure your security comes first

        Storage:
        • Single encrypted file (vault.dat)
        • Location: %s

        Credits:
        • Oogle
        • FlatLaf for the modern Swing Design
        """.formatted(getVaultPath().toAbsolutePath());
        JOptionPane.showMessageDialog(frame, msg, "About", JOptionPane.INFORMATION_MESSAGE);
    }

}
