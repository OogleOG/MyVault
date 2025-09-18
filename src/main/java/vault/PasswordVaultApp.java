package vault;

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
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
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
import java.util.regex.Pattern;

public class PasswordVaultApp {
    private static final Path VAULT_DIR = Paths.get(System.getProperty("user.home"), ".vault");
    private static final Path VAULT_PATH = VAULT_DIR.resolve("vault.dat");

    private static final byte[] MAGIC = new byte[]{'J','V','L','T'};
    private static final byte VERSION = 1;

    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int KEY_LEN_BITS = 256;
    private static final int PBKDF2_ITERS = 600_000;
    private static final String KDF_ALGO = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_ALGO = "AES/GCM/NoPadding";

    private static final SecureRandom RNG = new SecureRandom();
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public static class Entry {
        String id;
        String label;
        String username;
        String email;
        String password;
        long createdAt;
        long updatedAt;
    }
    public static class VaultData {
        String vaultName;
        List<Entry> entries = new ArrayList<>();
        long lastModified;
    }

    private JFrame frame;
    private JTable table;
    private JLabel statusLabel;
    private DefaultTableModel tableModel;
    private TableRowSorter<TableModel> sorter;
    private JTextField searchField;
    private char[] masterPassword;
    private VaultData data;

    private long lastInteraction = System.currentTimeMillis();
    private static final long IDLE_LOCK_MS = 5 * 60 * 1000;
    private Timer idleTimer;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new PasswordVaultApp().start());
    }

    private void start() {
        try { Files.createDirectories(VAULT_DIR); }
        catch (IOException e) { showError("Cannot create vault folder: " + e.getMessage()); return; }
        showUnlockOrInit();
    }
    private void showUnlockOrInit() {
        if (Files.exists(VAULT_PATH)) unlockExistingVault(); else initNewVault();
    }
    private void unlockExistingVault() {
        JPasswordField pf = new JPasswordField();
        int res = JOptionPane.showConfirmDialog(null, pf, "Enter Master Password", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;
        char[] mpw = pf.getPassword();
        try {
            VaultData vd = loadVault(VAULT_PATH, mpw);
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
        JPanel panel = new JPanel(new GridLayout(0,1,6,6));
        JPasswordField p1 = new JPasswordField();
        JPasswordField p2 = new JPasswordField();
        JTextField name = new JTextField("MyVault");
        panel.add(new JLabel("Vault Name:")); panel.add(name);
        panel.add(new JLabel("Create Master Password:")); panel.add(p1);
        panel.add(new JLabel("Confirm Master Password:")); panel.add(p2);
        int res = JOptionPane.showConfirmDialog(null, panel, "Initialize Vault", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (res != JOptionPane.OK_OPTION) return;
        if (!Arrays.equals(p1.getPassword(), p2.getPassword())) { showError("Passwords do not match."); initNewVault(); return; }
        char[] mpw = p1.getPassword();
        try {
            VaultData vd = new VaultData();
            vd.vaultName = name.getText().isBlank() ? "MyVault" : name.getText().trim();
            vd.lastModified = System.currentTimeMillis();
            saveVault(VAULT_PATH, vd, mpw);
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
        frame.setSize(900, 560);
        frame.setLocationRelativeTo(null);

        JPanel root = new JPanel(new BorderLayout(8,8));
        root.setBorder(new javax.swing.border.EmptyBorder(10,10,10,10));

        JPanel top = new JPanel(new BorderLayout(6,6));
        searchField = new JTextField();
        top.add(searchField, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        JButton addBtn = new JButton("Add");
        JButton editBtn = new JButton("Edit");
        JButton delBtn = new JButton("Delete");
        JButton copyUserBtn = new JButton("Copy User");
        JButton copyEmailBtn = new JButton("Copy Email");
        JButton copyPassBtn = new JButton("Copy Password");
        JButton changeMasterBtn = new JButton("Change Master");
        JButton lockBtn = new JButton("Lock");
        buttons.add(addBtn);buttons.add(editBtn);buttons.add(delBtn);
        buttons.add(copyUserBtn);buttons.add(copyEmailBtn);buttons.add(copyPassBtn);
        buttons.add(changeMasterBtn);buttons.add(lockBtn);
        top.add(buttons, BorderLayout.EAST);

        root.add(top, BorderLayout.NORTH);

        tableModel = new DefaultTableModel(new Object[]{"Label","Username","Email","Updated","ID"},0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        sorter = new TableRowSorter<>(table.getModel());
        table.setRowSorter(sorter);
        resizeColumns();
        refreshTable();

        root.add(new JScrollPane(table), BorderLayout.CENTER);

        // === Status bar ===
        // === Status bar ===
        statusLabel = new JLabel("Unlocked — entries: " + data.entries.size());

        JLabel creditsLabel = new JLabel("Built by Oogle ❤️");
        creditsLabel.setFont(creditsLabel.getFont().deriveFont(Font.ITALIC, 11f));
// Theme-aware subtle color
        Color subtle = UIManager.getColor("Label.disabledForeground");
        if (subtle != null) creditsLabel.setForeground(subtle);

        JPanel status = new JPanel(new BorderLayout());
        status.setBorder(new EmptyBorder(4, 0, 0, 0));
        status.add(statusLabel, BorderLayout.WEST); // left side
        status.add(creditsLabel, BorderLayout.EAST); // right side

        root.add(status, BorderLayout.SOUTH);



        searchField.getDocument().addDocumentListener(new DocumentListener() {
            void update() {
                String q = searchField.getText().trim();
                if (q.isEmpty()) sorter.setRowFilter(null);
                else sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(q)));
            }
            @Override public void insertUpdate(DocumentEvent e) { update(); }
            @Override public void removeUpdate(DocumentEvent e) { update(); }
            @Override public void changedUpdate(DocumentEvent e) { update(); }
        });

        addBtn.addActionListener(e -> onAdd());
        editBtn.addActionListener(e -> onEdit());
        delBtn.addActionListener(e -> onDelete());
        copyUserBtn.addActionListener(e -> copySelected("username"));
        copyEmailBtn.addActionListener(e -> copySelected("email"));
        copyPassBtn.addActionListener(e -> copySelected("password"));
        changeMasterBtn.addActionListener(e -> onChangeMaster());
        lockBtn.addActionListener(e -> lockAndReturnToUnlock());

        Toolkit.getDefaultToolkit().addAWTEventListener(ev -> lastInteraction = System.currentTimeMillis(),
                AWTEvent.KEY_EVENT_MASK | AWTEvent.MOUSE_EVENT_MASK | AWTEvent.MOUSE_MOTION_EVENT_MASK);

        idleTimer = new Timer(5_000, e -> {
            if (System.currentTimeMillis() - lastInteraction > IDLE_LOCK_MS) {
                idleTimer.stop();
                lockAndReturnToUnlock();
            }
        });
        idleTimer.start();

        frame.setContentPane(root);
        frame.setVisible(true);
    }
    private void resizeColumns() {
        TableColumnModel cols = table.getColumnModel();
        if (cols.getColumnCount() < 5) return;
        cols.getColumn(0).setPreferredWidth(220);
        cols.getColumn(1).setPreferredWidth(160);
        cols.getColumn(2).setPreferredWidth(200);
        cols.getColumn(3).setPreferredWidth(120);
        cols.getColumn(4).setPreferredWidth(80);
    }
    private void refreshTable() {
        tableModel.setRowCount(0);
        for (Entry e : data.entries) {
            tableModel.addRow(new Object[]{e.label, ns(e.username), ns(e.email), Instant.ofEpochMilli(e.updatedAt), e.id});
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
            if (edited.password != null) sel.password = edited.password;
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
    private void onChangeMaster() {
        JPasswordField p1 = new JPasswordField();
        JPasswordField p2 = new JPasswordField();
        JPanel panel = new JPanel(new GridLayout(0,1,6,6));
        panel.add(new JLabel("New Master Password:")); panel.add(p1);
        panel.add(new JLabel("Confirm New Password:")); panel.add(p2);
        int res = JOptionPane.showConfirmDialog(frame, panel, "Change Master Password", JOptionPane.OK_CANCEL_OPTION);
        if (res != JOptionPane.OK_OPTION) return;
        if (!Arrays.equals(p1.getPassword(), p2.getPassword())) { showError("Passwords do not match."); return; }
        char[] newMpw = p1.getPassword();
        try {
            saveVault(VAULT_PATH, data, newMpw);
            Arrays.fill(masterPassword, '\0');
            masterPassword = newMpw;
            showInfo("Master password updated.");
        } catch (Exception ex) {
            Arrays.fill(newMpw, '\0');
            showError("Failed to update master: " + ex.getMessage());
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
        showInfo("Copied " + field + " to clipboard (clears in ~15s)");
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
            saveVault(VAULT_PATH, data, masterPassword);
            refreshTable();
        } catch (Exception ex) { showError("Failed to save: " + ex.getMessage()); }
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

    private static void saveVault(Path p, VaultData data, char[] masterPassword) throws Exception {
        byte[] salt = new byte[SALT_LEN]; RNG.nextBytes(salt);
        SecretKey key = deriveKey(masterPassword, salt);
        byte[] iv = new byte[IV_LEN]; RNG.nextBytes(iv);
        byte[] plaintext = GSON.toJson(data).getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = encryptGCM(key, iv, plaintext);
        Path tmp = p.resolveSibling(p.getFileName().toString() + ".tmp");
        try (DataOutputStream out = new DataOutputStream(Files.newOutputStream(tmp, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))) {
            out.write(MAGIC); out.writeByte(VERSION);
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
            VaultData vd = GSON.fromJson(json, VaultData.class);
            return vd;
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
    private void showError(String msg) { JOptionPane.showMessageDialog(null, msg, "Error", JOptionPane.ERROR_MESSAGE); }
    private void showInfo(String msg) { JOptionPane.showMessageDialog(null, msg, "Info", JOptionPane.INFORMATION_MESSAGE); }

    private static class EntryForm {
        private final JDialog dialog;
        private final JTextField label = new JTextField();
        private final JTextField username = new JTextField();
        private final JTextField email = new JTextField();
        private final JPasswordField password = new JPasswordField();
        private Entry result;
        EntryForm(Frame owner, Entry existing) {
            dialog = new JDialog(owner, (existing == null ? "Add Entry" : "Edit Entry"), true);
            JPanel panel = new JPanel(new GridBagLayout());
            panel.setBorder(new EmptyBorder(10,10,10,10));
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(4,4,4,4);
            c.fill = GridBagConstraints.HORIZONTAL;
            c.gridx=0; c.gridy=0; panel.add(new JLabel("Label:"), c);
            c.gridx=1; c.weightx=1; panel.add(label, c);
            c.weightx=0;
            c.gridx=0; c.gridy=1; panel.add(new JLabel("Username:"), c);
            c.gridx=1; c.weightx=1; panel.add(username, c);
            c.weightx=0;
            c.gridx=0; c.gridy=2; panel.add(new JLabel("Email:"), c);
            c.gridx=1; c.weightx=1; panel.add(email, c);
            c.weightx=0;
            c.gridx=0; c.gridy=3; panel.add(new JLabel("Password:"), c);
            c.gridx=1; c.weightx=1; panel.add(password, c);
            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton ok = new JButton("OK"); JButton cancel = new JButton("Cancel");
            buttons.add(ok); buttons.add(cancel);
            ok.addActionListener(e -> {
                if (label.getText().trim().isEmpty()) { JOptionPane.showMessageDialog(dialog, "Label required"); return; }
                Entry e1 = new Entry();
                e1.label = label.getText().trim();
                e1.username = username.getText().trim();
                e1.email = email.getText().trim();
                char[] pw = password.getPassword();
                if (existing == null) { e1.password = new String(pw); }
                else { e1.password = (pw.length == 0) ? existing.password : new String(pw); }
                Arrays.fill(pw, '\0');
                result = e1; dialog.dispose();
            });
            cancel.addActionListener(e -> { result = null; dialog.dispose(); });
            if (existing != null) {
                label.setText(existing.label);
                username.setText(existing.username);
                email.setText(existing.email);
                password.setText("");
            }
            dialog.getContentPane().add(panel, BorderLayout.CENTER);
            dialog.getContentPane().add(buttons, BorderLayout.SOUTH);
            dialog.pack();
            dialog.setSize(420, dialog.getHeight());
            dialog.setLocationRelativeTo(owner);
        }
        Entry showDialog() { dialog.setVisible(true); return result; }
    }

    public static String computeMachineFingerprint() {
        String os = System.getProperty("os.name") + "|" + System.getProperty("os.arch") + "|" + System.getProperty("user.name");
        try {
            var md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(os.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(java.util.Arrays.copyOf(h, 16));
        } catch (Exception e) { return null; }
    }

}
