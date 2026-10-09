/// Beacon QUIC listener

function ListenerUI(mode_create)
{
    // MAIN SETTING
    let labelHost = form.create_label("Host & port (Bind):");
    let comboHostBind = form.create_combo();
    comboHostBind.setEnabled(mode_create)
    comboHostBind.clear();
    let addrs = ax.interfaces();
    for (let item of addrs) { comboHostBind.addItem(item); }
    let spinPortBind = form.create_spin();
    spinPortBind.setRange(1, 65535);
    spinPortBind.setValue(4433);
    spinPortBind.setEnabled(mode_create)

    let labelCallback = form.create_label("Callback addresses:");
    let textCallback = form.create_list();
    textCallback.setButtonsEnabled(true);
    textCallback.addItem("address:port");

    let labelEncryptKey = form.create_label("Encryption key:");
    let textlineEncryptKey = form.create_textline(ax.random_string(32, "hex"));
    textlineEncryptKey.setEnabled(mode_create)
    let buttonEncryptKey = form.create_button("Generate");
    buttonEncryptKey.setEnabled(mode_create)

    let certSelector = form.create_selector_file();
    certSelector.setPlaceholder("TLS Certificate (optional, auto-generate if empty)");
    let keySelector = form.create_selector_file();
    keySelector.setPlaceholder("TLS Key (optional, auto-generate if empty)");
    let layout_group = form.create_vlayout();
    layout_group.addWidget(certSelector);
    layout_group.addWidget(keySelector);
    let panel_group = form.create_panel();
    panel_group.setLayout(layout_group);
    let tls_group = form.create_groupbox("TLS Certificates", false)
    tls_group.setPanel(panel_group);

    form.connect(buttonEncryptKey, "clicked", function() { textlineEncryptKey.setText( ax.random_string(32, "hex") ); });

    let layoutMain = form.create_gridlayout();
    layoutMain.addWidget(labelHost,          0, 0, 1, 1);
    layoutMain.addWidget(comboHostBind,      0, 1, 1, 1);
    layoutMain.addWidget(spinPortBind,       0, 2, 1, 1);
    layoutMain.addWidget(labelCallback,      1, 0, 1, 1);
    layoutMain.addWidget(textCallback,       1, 1, 1, 2);
    layoutMain.addWidget(labelEncryptKey,    2, 0, 1, 1);
    layoutMain.addWidget(textlineEncryptKey, 2, 1, 1, 1);
    layoutMain.addWidget(buttonEncryptKey,   2, 2, 1, 1);
    layoutMain.addWidget(tls_group,          3, 0, 1, 3);

    let container = form.create_container();
    container.put("host_bind",          comboHostBind);
    container.put("port_bind",          spinPortBind);
    container.put("callback_addresses", textCallback);
    container.put("encrypt_key",        textlineEncryptKey);
    container.put("ssl_cert",           certSelector);
    container.put("ssl_key",            keySelector);

    let panel = form.create_panel();
    panel.setLayout(layoutMain);

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 600,
        ui_width: 700
    }
}
