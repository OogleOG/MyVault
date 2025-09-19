
package com.oogle.vaultpro;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.extras.FlatSVGIcon;
import com.oogle.vaultpro.crypto.Kdf;
import com.oogle.vaultpro.model.Entry;
import com.oogle.vaultpro.model.Settings;
import com.oogle.vaultpro.model.VaultData;
import com.oogle.vaultpro.service.AuditService;
import com.oogle.vaultpro.service.Generator;
import com.oogle.vaultpro.service.VaultStore;
import com.oogle.vaultpro.util.TotpUtil;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
    import java.nio.file.*;
import java.security.SecureRandom;
import java.util.List;
import java.util.*;
import java.util.prefs.Preferences;
import java.util.stream.Collectors;

public class VaultProApp {

    static {
        try { FlatDarkLaf.setup(); } catch (Exception ignored) {}
        UIManager.put("Component.arc", 16);
        UIManager.put("Button.arc", 16);
        UIManager.put("TextComponent.arc", 12);
        UIManager.put("Table.showHorizontalLines", Boolean.FALSE);
        UIManager.put("Table.showVerticalLines", Boolean.FALSE);
        UIManager.put("Table.intercellSpacing", new Dimension(0, 8));
        UIManager.put("ScrollBar.thumbArc", 999);
        UIManager.put("ScrollBar.showButtons", Boolean.FALSE);
        UIManager.put("TabbedPane.tabSeparatorsFullHeight", Boolean.TRUE);
    }

    private final Settings settings = new Settings();
    private final VaultStore store = new VaultStore();
    private final Generator generator = new Generator();

    private JFrame frame;
    private JTable table;
    private DefaultTableModel model;
    private TableRowSorter<TableModel> sorter;
    private JTextField search;
    private JList<String> sidebar;
    private DefaultListModel<String> sidebarModel;

    private char[] masterPassword;
    private VaultData data;

    private long lastInteraction = System.currentTimeMillis();
    private javax.swing.Timer idleTimer;

    // Unsaved changes
    private boolean dirty = false;

    // Icons and early owner
    private List<Image> appIcons;
    private JFrame loginOwner;

    // Preferences (persist last vault path and dir)
    private final Preferences prefs = Preferences.userNodeForPackage(VaultProApp.class);
    private Path vaultPath;
    private Path lastDir;

    // Status bar labels
    private JLabel statusLabel;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new VaultProApp().start());
    }

    private void start() {
        try {
            String prev = prefs.get("vaultPath", "");
            if (prev != null && !prev.isBlank()) {
                vaultPath = Paths.get(prev);
                lastDir = vaultPath.getParent();
            } else {
                Path def = getDefaultVaultPath();
                Files.createDirectories(def.getParent());
                vaultPath = def;
                lastDir = def.getParent();
            }
        } catch (Exception ignored) {}
        setTaskbarIcon();
        if (Files.exists(vaultPath)) unlockExisting(); else createNew();
    }

    private Path getDefaultVaultPath() {
        return Paths.get(System.getProperty("user.home"), ".vault", "vault.dat");
    }

    /* ================== Icons ================== */

    private List<Image> loadAppIcons() {
        List<Image> list = new ArrayList<>();
        int[] sizes = {16, 24, 32, 48, 64, 128, 256, 512};
        ClassLoader cl = getClass().getClassLoader();
        for (int s : sizes) {
            String path = String.format("icons/app-icon-%d.png", s);
            java.net.URL url = cl.getResource(path);
            if (url != null) list.add(new ImageIcon(url).getImage());
        }
        return list;
    }

    private void setTaskbarIcon() {
        try {
            if (java.awt.Taskbar.isTaskbarSupported()) {
                if (appIcons == null || appIcons.isEmpty()) appIcons = loadAppIcons();
                if (!appIcons.isEmpty()) java.awt.Taskbar.getTaskbar().setIconImage(appIcons.get(appIcons.size()-1));
            }
        } catch (Exception ignored) {}
    }

    private JFrame ensureOwnerFrame() {
        if (frame != null) return frame;
        if (loginOwner == null) {
            loginOwner = new JFrame();
            loginOwner.setUndecorated(true);
            if (appIcons == null) appIcons = loadAppIcons();
            loginOwner.setIconImages(appIcons);
            loginOwner.setType(Window.Type.UTILITY);
            loginOwner.setLocationRelativeTo(null);
        }
        return loginOwner;
    }

    private int showConfirmWithIcon(Window owner, String title, JComponent content) {
        JOptionPane pane = new JOptionPane(content, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION);
        JDialog dlg = pane.createDialog(owner, title);
        if (appIcons == null) appIcons = loadAppIcons();
        if (!appIcons.isEmpty()) dlg.setIconImages(appIcons);
        dlg.setResizable(true);
        dlg.setVisible(true);
        Object v = pane.getValue();
        return (v instanceof Integer) ? (Integer) v : JOptionPane.CLOSED_OPTION;
    }

    /* ================== Auth ================== */

    private void unlockExisting() {
        JPasswordField pf = new JPasswordField();
        int ok = showConfirmWithIcon(ensureOwnerFrame(), "Enter Master Password", pf);
        if (ok != JOptionPane.OK_OPTION) return;
        char[] mpw = pf.getPassword();
        try {
            this.data = store.load(vaultPath, mpw);
            this.masterPassword = mpw;
            buildUI();
        } catch (Exception ex) {
            Arrays.fill(mpw, '\0');
            error("Failed to open vault: " + ex.getMessage());
            unlockExisting();
        }
    }

    private void createNew() {
        JTextField name = new JTextField("MyVault");
        JPasswordField p1 = new JPasswordField();
        JPasswordField p2 = new JPasswordField();
        JPanel form = formPanel();
        form.add(new JLabel("Vault name:")); form.add(name);
        form.add(new JLabel("Master password:")); form.add(p1);
        form.add(new JLabel("Repeat:")); form.add(p2);
        int ok = showConfirmWithIcon(ensureOwnerFrame(), "Create Vault", form);
        if (ok != JOptionPane.OK_OPTION) return;
        if (!Arrays.equals(p1.getPassword(), p2.getPassword())) { error("Passwords don't match"); return; }
        char[] mpw = p1.getPassword();
        try {
            this.data = new VaultData();
            data.vaultName = name.getText().trim().isBlank() ? "MyVault" : name.getText().trim();
            Kdf.Params kdf = Kdf.newParamsPBKDF2(new SecureRandom(), settings.pbkdf2Iters, 16);
            store.saveV2(vaultPath, mpw, data, kdf);
            this.masterPassword = mpw;
            buildUI();
        } catch (Exception ex) {
            Arrays.fill(mpw, '\0');
            error("Failed to create vault: " + ex.getMessage());
        }
    }

    /* ================== UI ================== */

    private void buildUI() {
        frame = new JFrame();
        if (appIcons == null) appIcons = loadAppIcons();
        if (!appIcons.isEmpty()) frame.setIconImages(appIcons);
        updateTitle();
        frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        frame.setSize(1180, 720);
        frame.setLocationRelativeTo(null);

        // Menu bar (Vault, Help)
        frame.setJMenuBar(createMenuBar());

        // Toolbar
        JToolBar tb = new JToolBar(); tb.setFloatable(false);
        tb.setBorder(new EmptyBorder(8,8,8,8));
        JButton addBtn = iconButton("icons/add.svg", "New (Ctrl+N)"); addBtn.addActionListener(a -> addEntryDialog());
        JButton genBtn = iconButton("icons/gen.svg", "Generator"); genBtn.addActionListener(a -> showGenerator());
        JButton auditBtn = iconButton("icons/audit.svg", "Audit"); auditBtn.addActionListener(a -> runAudit());
        JButton saveBtn = iconButton("icons/save.svg", "Save (Ctrl+S)"); saveBtn.addActionListener(a -> saveVault());
        JButton lockBtn = iconButton("icons/lock.svg", "Lock"); lockBtn.addActionListener(a -> lock());
        search = new JTextField(); search.putClientProperty("JTextField.placeholderText","Search…");
        tb.add(addBtn); tb.addSeparator(); tb.add(genBtn); tb.add(auditBtn);
        tb.add(Box.createHorizontalGlue()); tb.add(search); tb.add(Box.createHorizontalStrut(12));
        tb.add(saveBtn); tb.add(lockBtn);

        // Sidebar
        sidebarModel = new DefaultListModel<>();
        sidebar = new JList<>(sidebarModel);
        sidebar.setBorder(new EmptyBorder(8,8,8,8));
        sidebar.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        refreshSidebar();
        sidebar.addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) applySearchFilter(); });

        // Table
        model = new DefaultTableModel(new Object[]{"★","Label","Username","URL","Tags"},0){
            @Override public boolean isCellEditable(int r, int c){ return false; }
            @Override public Class<?> getColumnClass(int c){ return c==0?Boolean.class:String.class; }
        };
        table = new JTable(model);
        table.setRowHeight(28);
        table.setFillsViewportHeight(true);
        table.setShowGrid(false);
        sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        table.getColumnModel().getColumn(0).setMaxWidth(50);
        table.getColumnModel().getColumn(4).setPreferredWidth(250);
        table.getColumnModel().getColumn(0).setCellRenderer(new StarRenderer());
        table.getColumnModel().getColumn(4).setCellRenderer(new TagRenderer());
        refreshTable();

        // Layout
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                wrap(sidebar), new JScrollPane(table));
        split.setDividerLocation(220);
        split.setResizeWeight(0);

        JPanel root = new JPanel(new BorderLayout());
        root.add(tb, BorderLayout.NORTH);
        root.add(split, BorderLayout.CENTER);

        // Status bar with credits
        JPanel status = new JPanel(new BorderLayout());
        status.setBorder(new EmptyBorder(4, 0, 0, 0));
        statusLabel = new JLabel("Unlocked - Ready");
        JLabel credits = new JLabel("Built by Oogle ❤️");
        credits.setFont(credits.getFont().deriveFont(Font.ITALIC, 11f));
        Color subtle = UIManager.getColor("Label.disabledForeground");
        if (subtle != null) credits.setForeground(subtle);
        status.add(statusLabel, BorderLayout.WEST);
        status.add(credits, BorderLayout.EAST);
        root.add(status, BorderLayout.SOUTH);

        frame.setContentPane(root);
        frame.setVisible(true);

        // Listeners
        search.getDocument().addDocumentListener(new DocumentListener() {
            void run(){ applySearchFilter(); }
            @Override public void insertUpdate(DocumentEvent e){ run(); }
            @Override public void removeUpdate(DocumentEvent e){ run(); }
            @Override public void changedUpdate(DocumentEvent e){ run(); }
        });

        table.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount()==2 && table.getSelectedRow()>=0) {
                    int row = table.convertRowIndexToModel(table.getSelectedRow());
                    editEntryDialog(data.entries.get(row));
                } else if (SwingUtilities.isRightMouseButton(e)) {
                    int r = table.rowAtPoint(e.getPoint());
                    if (r>=0) {
                        table.setRowSelectionInterval(r,r);
                        showRowPopup(e, data.entries.get(table.convertRowIndexToModel(r)));
                    }
                }
            }
        });

        // Shortcuts
        frame.getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke("control S"), "save");
        frame.getRootPane().getActionMap().put("save", new AbstractAction(){ public void actionPerformed(java.awt.event.ActionEvent e){ saveVault(); }});
        frame.getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke("control N"), "new");
        frame.getRootPane().getActionMap().put("new", new AbstractAction(){ public void actionPerformed(java.awt.event.ActionEvent e){ addEntryDialog(); }});
        frame.getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke("control O"), "open");
        frame.getRootPane().getActionMap().put("open", new AbstractAction(){ public void actionPerformed(java.awt.event.ActionEvent e){ openVault(); }});
        frame.getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke("control shift S"), "saveas");
        frame.getRootPane().getActionMap().put("saveas", new AbstractAction(){ public void actionPerformed(java.awt.event.ActionEvent e){ saveAs(); }});
        frame.getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke("F1"), "help");
        frame.getRootPane().getActionMap().put("help", new AbstractAction(){ public void actionPerformed(java.awt.event.ActionEvent e){ showHelp(); }});

        // Auto-lock + activity
        idleTimer = new javax.swing.Timer(1000, ev -> { if (System.currentTimeMillis()-lastInteraction > settings.autoLockMs) lock(); });
        idleTimer.start();
        Toolkit.getDefaultToolkit().addAWTEventListener(e -> lastInteraction = System.currentTimeMillis(),
                AWTEvent.MOUSE_EVENT_MASK | AWTEvent.KEY_EVENT_MASK);

        // Confirm close handler
        frame.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override public void windowClosing(java.awt.event.WindowEvent e) {
                if (confirmCloseIfDirty()) {
                    frame.dispose();
                }
            }
        });
    }

    private JMenuBar createMenuBar() {
        JMenuBar mb = new JMenuBar();

        JMenu mVault = new JMenu("Vault");
        JMenuItem miOpen = new JMenuItem("Open Vault…"); miOpen.setAccelerator(KeyStroke.getKeyStroke("control O"));
        JMenuItem miSaveAs = new JMenuItem("Save As…");  miSaveAs.setAccelerator(KeyStroke.getKeyStroke("control shift S"));
        JMenuItem miExit = new JMenuItem("Exit");
        miOpen.addActionListener(e -> openVault());
        miSaveAs.addActionListener(e -> saveAs());
        miExit.addActionListener(e -> { if (confirmCloseIfDirty()) frame.dispose(); });
        mVault.add(miOpen); mVault.add(miSaveAs); mVault.addSeparator(); mVault.add(miExit);

        JMenu mHelp = new JMenu("Help");
        JMenuItem miHelp = new JMenuItem("Help"); miHelp.setAccelerator(KeyStroke.getKeyStroke("F1"));
        JMenuItem miAbout = new JMenuItem("About");
        miHelp.addActionListener(e -> showHelp());
        miAbout.addActionListener(e -> showAbout());
        mHelp.add(miHelp); mHelp.addSeparator(); mHelp.add(miAbout);

        mb.add(mVault);
        mb.add(mHelp);
        return mb;
    }

    /* ================== Menu actions ================== */

    private void openVault() {
        if (!confirmCloseIfDirty()) return;
        JFileChooser fc = new JFileChooser(lastDir != null ? lastDir.toFile() : new File(System.getProperty("user.home")));
        fc.setDialogTitle("Open Vault (.dat)");
        fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
        if (fc.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            File sel = fc.getSelectedFile();
            lastDir = sel.getParentFile().toPath();
            prefs.put("lastDir", lastDir.toString());
            Path newPath = sel.toPath();
            JPasswordField pf = new JPasswordField();
            int ok = showConfirmWithIcon(frame, "Enter Master Password", pf);
            if (ok != JOptionPane.OK_OPTION) return;
            char[] mpw = pf.getPassword();
            try {
                // switch
                this.data = store.load(newPath, mpw);
                this.masterPassword = mpw;
                this.vaultPath = newPath;
                prefs.put("vaultPath", vaultPath.toString());
                dirty = false;
                // rebuild UI
                frame.dispose();
                buildUI();
            } catch (Exception ex) {
                Arrays.fill(mpw, '\0');
                error("Failed to open: " + ex.getMessage());
            }
        }
    }

    private void saveAs() {
        JFileChooser fc = new JFileChooser(lastDir != null ? lastDir.toFile() : new File(System.getProperty("user.home")));
        fc.setDialogTitle("Save Vault As");
        fc.setSelectedFile(vaultPath != null ? vaultPath.toFile() : new File("vault.dat"));
        if (fc.showSaveDialog(frame) == JFileChooser.APPROVE_OPTION) {
            File sel = fc.getSelectedFile();
            Path newPath = sel.toPath();
            // Optional: enforce .dat extension
            if (!newPath.toString().toLowerCase().endsWith(".dat")) {
                newPath = newPath.resolveSibling(newPath.getFileName().toString() + ".dat");
            }
            if (Files.exists(newPath)) {
                int overwrite = JOptionPane.showConfirmDialog(frame, "File exists. Overwrite?", "Confirm", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
                if (overwrite != JOptionPane.OK_OPTION) return;
            }
            try {
                Kdf.Params kdf = Kdf.newParamsPBKDF2(new SecureRandom(), settings.pbkdf2Iters, 16);
                store.saveV2(newPath, masterPassword, data, kdf);
                this.vaultPath = newPath;
                this.lastDir = newPath.getParent();
                prefs.put("vaultPath", vaultPath.toString());
                prefs.put("lastDir", lastDir.toString());
                dirty = false;
                updateTitle();
                info("Saved to: " + newPath);
            } catch (Exception ex) {
                error("Save As failed: " + ex.getMessage());
            }
        }
    }

    private void showHelp() {
        String html = """
                <html>
                <h2>Getting Started</h2>
                <ol>
                  <li>Click <b>Add</b> to create an entry (label, username, password, URL, tags).</li>
                  <li>Right‑click a row for <i>Copy Username/Password</i>, <i>Reveal</i>, or <i>Delete</i>.</li>
                  <li>Use the <b>Generator</b> for strong passwords (auto‑clears clipboard).</li>
                  <li><b>Audit</b> flags weak, reused, and old passwords.</li>
                  <li>Use <b>Vault → Save As…</b> to move your <code>.dat</code> file.</li>
                  <li>Press <b>Ctrl+S</b> to save, <b>Ctrl+O</b> to open another vault, <b>F1</b> for help.</li>
                </ol>
                <p>Your vault is end‑to‑end encrypted. The master password is never stored.</p>
                </html>
                """;
        JOptionPane.showMessageDialog(frame, new JLabel(html), "Help", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showAbout() {
        String html = """
                <html>
                  <h2>MyVault Pro</h2>
                  <p>Built by Oogle ❤️</p>
                  <p>Version 2.0 (Modern UI)</p>
                  <p>AES‑GCM with KEK/DEK, PBKDF2‑SHA256, local vault.</p>
                </html>
                """;
        JOptionPane pane = new JOptionPane(new JLabel(html), JOptionPane.INFORMATION_MESSAGE, JOptionPane.DEFAULT_OPTION);
        JDialog dlg = pane.createDialog(frame, "About");
        if (appIcons == null) appIcons = loadAppIcons();
        if (!appIcons.isEmpty()) dlg.setIconImages(appIcons);
        dlg.setResizable(true);
        dlg.setVisible(true);
    }

    /* ================== Rendering helpers ================== */

    private static JPanel wrap(JComponent c){
        JPanel p = new JPanel(new BorderLayout());
        JLabel t = new JLabel("Filters");
        t.setBorder(new EmptyBorder(8,8,0,8));
        p.add(t, BorderLayout.NORTH);
        p.add(new JScrollPane(c), BorderLayout.CENTER);
        return p;
    }
    private JPanel formPanel(){
        JPanel g = new JPanel(new GridLayout(0,1,8,8));
        g.setBorder(new EmptyBorder(10,10,10,10));
        return g;
    }
    private JButton iconButton(String resPath, String tooltip){
        JButton b = new JButton(new FlatSVGIcon(resPath, 16,16));
        b.setToolTipText(tooltip);
        return b;
    }

    private static class StarRenderer extends DefaultTableCellRenderer {
        private final Icon star = new FlatSVGIcon("icons/star.svg", 16,16);
        @Override public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column){
            Component c = super.getTableCellRendererComponent(table, "", isSelected, hasFocus, row, column);
            setHorizontalAlignment(CENTER);
            boolean fav = Boolean.TRUE.equals(value);
            setIcon(fav ? star : null);
            return c;
        }
    }
    private static class TagRenderer extends DefaultTableCellRenderer {
        @Override public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column){
            JLabel l = (JLabel) super.getTableCellRendererComponent(table, "", isSelected, hasFocus, row, column);
            String tags = value==null ? "" : value.toString();
            l.setText(tags);
            l.setBorder(new EmptyBorder(0,6,0,6));
            return l;
        }
    }

    /* ================== Filters ================== */

    private void refreshSidebar(){
        sidebarModel.clear();
        sidebarModel.addElement("All");
        sidebarModel.addElement("Favorites");
        sidebarModel.addElement("Weak");
        sidebarModel.addElement("Reused");
        sidebarModel.addElement("Old");
        Set<String> tags = new TreeSet<>();
        if (data != null) for (Entry e : data.entries) tags.addAll(e.tags);
        for (String t : tags) sidebarModel.addElement("tag:" + t);
        sidebar.setSelectedIndex(0);
    }

    private void applySearchFilter(){
        String q = search.getText().trim().toLowerCase();
        String sel = sidebar.getSelectedValue();
        AuditService.AuditResult audit = null;
        if ("Weak".equals(sel) || "Reused".equals(sel) || "Old".equals(sel)) {
            audit = new AuditService().run(data);
        }
        AuditService.AuditResult finalAudit = audit;
        sorter.setRowFilter(new RowFilter<>(){
            @Override public boolean include(Entry<? extends TableModel, ? extends Integer> ei){
                int r = ei.getIdentifier();
                String label = (String) model.getValueAt(r,1);
                String user = (String) model.getValueAt(r,2);
                String url = (String) model.getValueAt(r,3);
                String tags = (String) model.getValueAt(r,4);
                boolean matchesSearch = q.isEmpty() ||
                        (label!=null && label.toLowerCase().contains(q)) ||
                        (user!=null && user.toLowerCase().contains(q)) ||
                        (url!=null && url.toLowerCase().contains(q)) ||
                        (tags!=null && tags.toLowerCase().contains(q));
                if (!matchesSearch) return false;

                String s = sidebar.getSelectedValue();
                if (s==null || "All".equals(s)) return true;
                if ("Favorites".equals(s)) return Boolean.TRUE.equals(model.getValueAt(r,0));
                if (s.startsWith("tag:")) {
                    String t = s.substring(4).toLowerCase();
                    return tags!=null && Arrays.stream(tags.split(",")).map(String::trim).anyMatch(x -> x.equalsIgnoreCase(t));
                }
                if (finalAudit != null) {
                    com.oogle.vaultpro.model.Entry entry = data.entries.get(r);
                    switch (s) {
                        case "Weak" -> {
                            return finalAudit.weak.contains(entry);
                        }
                        case "Reused" -> {
                            for (var group : finalAudit.reused) if (group.contains(entry)) return true;
                            return false;
                        }
                        case "Old" -> {
                            return finalAudit.old.contains(entry);
                        }
                    }
                }
                return true;
            }
        });
    }

    /* ================== Data & dialogs ================== */

    private void refreshTable(){
        model.setRowCount(0);
        for (Entry e : data.entries) {
            model.addRow(new Object[]{ e.favorite, e.label, e.username, e.url, String.join(",", e.tags) });
        }
    }

    private void showRowPopup(MouseEvent e, Entry entry){
        JPopupMenu m = new JPopupMenu();
        JMenuItem copyUser = new JMenuItem("Copy Username", new FlatSVGIcon("icons/copy.svg",16,16));
        JMenuItem copyPass = new JMenuItem("Copy Password", new FlatSVGIcon("icons/copy.svg",16,16));
        JMenuItem reveal = new JMenuItem("Reveal Password");
        JMenuItem totp = new JMenuItem("Copy TOTP (if set)");
        JMenuItem delete = new JMenuItem("Delete");
        m.add(copyUser); m.add(copyPass); m.add(reveal); m.add(totp); m.addSeparator(); m.add(delete);
        copyUser.addActionListener(a -> copyWithAutoClear(entry.username));
        copyPass.addActionListener(a -> copyWithAutoClear(entry.password));
        reveal.addActionListener(a -> JOptionPane.showMessageDialog(frame, entry.password, "Password", JOptionPane.INFORMATION_MESSAGE));
        totp.addActionListener(a -> copyTotp(entry.otpSecret));
        delete.addActionListener(a -> { data.entries.remove(entry); refreshTable(); refreshSidebar(); markDirty(); });
        m.show(table, e.getX(), e.getY());
    }

    private void copyTotp(String base32){
        if (base32 == null || base32.isBlank()) { info("No OTP secret set."); return; }
        try {
            int code = TotpUtil.totp(base32, System.currentTimeMillis(), 30, 6);
            copyWithAutoClear(String.format("%06d", code));
            info("TOTP copied to clipboard.");
        } catch (Exception ex) {
            error("TOTP error: " + ex.getMessage());
        }
    }

    private void addEntryDialog(){
        Entry e = new Entry();
        e.id = UUID.randomUUID().toString();
        e.createdAt = e.updatedAt = System.currentTimeMillis();
        editEntryDialog(e);
        if (!data.entries.contains(e) && e.label != null) {
            data.entries.add(e);
            refreshTable();
            refreshSidebar();
            markDirty();
        }
    }

    private GridBagConstraints gbc(GridBagConstraints base, int x, int y, int w, int h, double wx, int fill) {
        GridBagConstraints c = (GridBagConstraints) base.clone();
        c.gridx = x; c.gridy = y; c.gridwidth = w; c.gridheight = h; c.weightx = wx; c.fill = fill;
        return c;
    }

    private void editEntryDialog(Entry e){
        JTextField label = new JTextField(e.label==null?"":e.label);
        JTextField user = new JTextField(e.username==null?"":e.username);
        JTextField url = new JTextField(e.url==null?"":e.url);
        JPasswordField pw = new JPasswordField(e.password==null?"":e.password);
        JTextField otp = new JTextField(e.otpSecret==null?"":e.otpSecret);
        JTextField tags = new JTextField(String.join(",", e.tags));
        JTextArea notes = new JTextArea(e.notes==null?"":e.notes,6,40);
        JCheckBox fav = new JCheckBox("Favorite", e.favorite);
        notes.setLineWrap(true); notes.setWrapStyleWord(true);

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(new EmptyBorder(12,12,12,12));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(6,6,6,6);
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 0; g.weighty = 0;

        // two columns
        form.add(new JLabel("Label:"), gbc(g,0,0,1,1,0,GridBagConstraints.HORIZONTAL));
        form.add(label,               gbc(g,1,0,1,1,1,GridBagConstraints.HORIZONTAL));
        form.add(new JLabel("Username:"), gbc(g,2,0,1,1,0,GridBagConstraints.HORIZONTAL));
        form.add(user,                   gbc(g,3,0,1,1,1,GridBagConstraints.HORIZONTAL));

        form.add(new JLabel("URL:"),  gbc(g,0,1,1,1,0,GridBagConstraints.HORIZONTAL));
        form.add(url,                 gbc(g,1,1,1,1,1,GridBagConstraints.HORIZONTAL));
        form.add(new JLabel("Password:"), gbc(g,2,1,1,1,0,GridBagConstraints.HORIZONTAL));
        form.add(pw,                      gbc(g,3,1,1,1,1,GridBagConstraints.HORIZONTAL));

        form.add(new JLabel("OTP Secret (Base32):"), gbc(g,0,2,1,1,0,GridBagConstraints.HORIZONTAL));
        form.add(otp,                             gbc(g,1,2,1,1,1,GridBagConstraints.HORIZONTAL));
        form.add(new JLabel("Tags (comma-separated):"), gbc(g,2,2,1,1,0,GridBagConstraints.HORIZONTAL));
        form.add(tags,                                gbc(g,3,2,1,1,1,GridBagConstraints.HORIZONTAL));

        form.add(new JLabel("Notes:"), gbc(g,0,3,4,1,0,GridBagConstraints.HORIZONTAL));
        JScrollPane notesScroll = new JScrollPane(notes);
        notesScroll.setPreferredSize(new Dimension(0, 140));
        form.add(notesScroll,          gbc(g,0,4,4,1,1,GridBagConstraints.BOTH));

        JPanel favRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        favRow.add(fav);
        form.add(favRow, gbc(g,0,5,4,1,0,GridBagConstraints.HORIZONTAL));

        JScrollPane scroller = new JScrollPane(form);
        scroller.setBorder(null);
        scroller.setPreferredSize(new Dimension(820, 480));
        scroller.getVerticalScrollBar().setUnitIncrement(16);

        JOptionPane pane = new JOptionPane(scroller, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION);
        JDialog dlg = pane.createDialog(frame, "Edit Entry");
        if (appIcons == null) appIcons = loadAppIcons();
        if (!appIcons.isEmpty()) dlg.setIconImages(appIcons);
        dlg.setResizable(true);
        dlg.pack();
        dlg.setSize(new Dimension(Math.max(820, dlg.getWidth()),
                                  Math.min(680, Toolkit.getDefaultToolkit().getScreenSize().height - 100)));
        dlg.setLocationRelativeTo(frame);
        dlg.setVisible(true);

        Object res = pane.getValue();
        if (!(res instanceof Integer) || ((Integer) res) != JOptionPane.OK_OPTION) return;

        String newPw = new String(pw.getPassword());
        if (e.password != null && !e.password.equals(newPw)) {
            Entry.PasswordHistory h = new Entry.PasswordHistory();
            h.password = e.password; h.changedAt = System.currentTimeMillis();
            e.history.add(0, h);
            e.pwRevision++;
        }
        e.label = label.getText().trim();
        e.username = user.getText().trim();
        e.url = url.getText().trim();
        e.password = newPw;
        e.otpSecret = otp.getText().trim().isEmpty()?null:otp.getText().trim();
        e.tags = Arrays.stream(tags.getText().split(",")).map(String::trim).filter(s->!s.isEmpty()).collect(Collectors.toList());
        e.notes = notes.getText();
        e.favorite = fav.isSelected();
        e.updatedAt = System.currentTimeMillis();

        refreshTable();
        refreshSidebar();
        markDirty();
    }

    // === Password Generator dialog ===
    private void showGenerator() {
        JSpinner len = new JSpinner(new SpinnerNumberModel(16, 8, 64, 1));
        JCheckBox upper = new JCheckBox("Uppercase", true);
        JCheckBox lower = new JCheckBox("Lowercase", true);
        JCheckBox digits = new JCheckBox("Digits", true);
        JCheckBox symbols = new JCheckBox("Symbols", true);

        JPanel p = new JPanel(new GridLayout(0, 1, 8, 8));
        p.setBorder(new EmptyBorder(10, 10, 10, 10));
        p.add(new JLabel("Length:"));
        p.add(len);
        p.add(upper);
        p.add(lower);
        p.add(digits);
        p.add(symbols);

        int ok = showConfirmWithIcon(frame, "Password Generator", p);
        if (ok == JOptionPane.OK_OPTION) {
            String g = generator.generate(
                    (int) len.getValue(),
                    upper.isSelected(),
                    lower.isSelected(),
                    digits.isSelected(),
                    symbols.isSelected()
            );
            copyWithAutoClear(g);
            if (statusLabel != null) statusLabel.setText("Generated password copied (" + settings.clipboardClearSeconds + "s)");
            JOptionPane.showMessageDialog(frame,
                    "Generated password copied to clipboard.\nIt will auto-clear in " + settings.clipboardClearSeconds + " seconds.",
                    "Generator",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }

    // === Security Audit dialog ===
    private void runAudit() {
        AuditService.AuditResult r = new AuditService().run(data);

        StringBuilder sb = new StringBuilder();
        sb.append("Weak passwords: ").append(r.weak.size()).append("\n");
        sb.append("Reused groups: ").append(r.reused.size()).append("\n");
        sb.append("Old passwords (>180 days): ").append(r.old.size()).append("\n\n");

        if (!r.weak.isEmpty()) {
            sb.append("Weak:\n");
            for (Entry e : r.weak) sb.append("  • ").append(e.label).append("\n");
            sb.append("\n");
        }
        if (!r.reused.isEmpty()) {
            sb.append("Reused:\n");
            for (var group : r.reused) {
                sb.append("  • ");
                for (int i = 0; i < group.size(); i++) {
                    sb.append(group.get(i).label);
                    if (i < group.size() - 1) sb.append(", ");
                }
                sb.append("\n");
            }
            sb.append("\n");
        }
        if (!r.old.isEmpty()) {
            sb.append("Old:\n");
            for (Entry e : r.old) sb.append("  • ").append(e.label).append("\n");
            sb.append("\n");
        }

        JTextArea area = new JTextArea(sb.toString(), 18, 60);
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane sp = new JScrollPane(area);

        JOptionPane pane = new JOptionPane(sp, JOptionPane.INFORMATION_MESSAGE, JOptionPane.DEFAULT_OPTION);
        JDialog dlg = pane.createDialog(frame, "Audit Report");
        if (appIcons == null) appIcons = loadAppIcons();
        if (!appIcons.isEmpty()) dlg.setIconImages(appIcons);
        dlg.setResizable(true);
        dlg.setVisible(true);

        if (statusLabel != null) statusLabel.setText("Audit: weak=" + r.weak.size() + ", reused=" + r.reused.size() + ", old=" + r.old.size());
        applySearchFilter();
    }


    /* ================== Dirty/save/close ================== */

    private void saveVault(){
        try {
            data.lastModified = System.currentTimeMillis();
            data.vaultRevision++;
            Kdf.Params kdf = Kdf.newParamsPBKDF2(new SecureRandom(), settings.pbkdf2Iters, 16);
            store.saveV2(vaultPath, masterPassword, data, kdf);
            dirty = false;
            updateTitle();
            info("Vault saved.");
        } catch (Exception ex) {
            error("Save failed: " + ex.getMessage());
        }
    }

    private boolean saveVaultSilently(){
        try {
            data.lastModified = System.currentTimeMillis();
            data.vaultRevision++;
            Kdf.Params kdf = Kdf.newParamsPBKDF2(new SecureRandom(), settings.pbkdf2Iters, 16);
            store.saveV2(vaultPath, masterPassword, data, kdf);
            dirty = false;
            updateTitle();
            return true;
        } catch (Exception ex) {
            error("Save failed: " + ex.getMessage());
            return false;
        }
    }

    private boolean confirmCloseIfDirty(){
        if (!dirty) return true;
        Object[] options = { "Save and Exit", "Don't Save", "Cancel" };
        int choice = JOptionPane.showOptionDialog(frame,
                "You have unsaved changes. Save before exiting?",
                "Unsaved changes",
                JOptionPane.YES_NO_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE,
                null, options, options[0]);
        if (choice == JOptionPane.YES_OPTION) {
            return saveVaultSilently();
        } else return choice == JOptionPane.NO_OPTION;
    }

    private void lock(){
        if (!confirmCloseIfDirty()) return;
        if (frame != null) frame.dispose();
        if (idleTimer != null) idleTimer.stop();
        if (masterPassword != null) Arrays.fill(masterPassword, '\0');
        masterPassword = null; data = null;
        unlockExisting();
    }

    private void markDirty(){ dirty = true; updateTitle(); }
    private void updateTitle(){
        String dot = dirty ? "• " : "";
        frame.setTitle(dot + data.vaultName + " — Pro " + "(" + vaultPath.getFileName() + ")");
    }

    /* ================== Utils ================== */

    private void copyWithAutoClear(String text){
        var cb = Toolkit.getDefaultToolkit().getSystemClipboard();
        var sel = new StringSelection(text);
        cb.setContents(sel, null);
        new javax.swing.Timer(settings.clipboardClearSeconds * 1000, e -> {
            try {
                var t = cb.getContents(null);
                String cur = (String) t.getTransferData(DataFlavor.stringFlavor);
                if (Objects.equals(cur, text)) cb.setContents(new StringSelection(""), null);
            } catch (Exception ignored) {}
        }) {{ setRepeats(false); }}.start();
    }
    private void info(String msg){ JOptionPane.showMessageDialog(frame, msg, "Info", JOptionPane.INFORMATION_MESSAGE); }
    private void error(String msg){ JOptionPane.showMessageDialog(frame, msg, "Error", JOptionPane.ERROR_MESSAGE); }
}
