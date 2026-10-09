/// Beacon UDP listener

function ListenerUI(mode_create)
{
    let spacer1 = form.create_vspacer()

    // MAIN SETTING
    let labelHost = form.create_label("Host & port (Bind):");
    let comboHostBind = form.create_combo();
    comboHostBind.setEnabled(mode_create)
    comboHostBind.clear();
    let addrs = ax.interfaces();
    for (let item of addrs) { comboHostBind.addItem(item); }
    let spinPortBind = form.create_spin();
    spinPortBind.setRange(1, 65535);
    spinPortBind.setValue(5353);
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

    let labelMaxPacket = form.create_label("Max packet size:");
    let spinMaxPacket = form.create_spin();
    spinMaxPacket.setRange(512, 65507);
    spinMaxPacket.setValue(65507);

    let spacer2 = form.create_vspacer()

    form.connect(buttonEncryptKey, "clicked", function() { textlineEncryptKey.setText( ax.random_string(32, "hex") ); });

    let layout = form.create_gridlayout();
    layout.addWidget(spacer1,            0, 0, 1, 3);
    layout.addWidget(labelHost,          1, 0, 1, 1);
    layout.addWidget(comboHostBind,      1, 1, 1, 1);
    layout.addWidget(spinPortBind,       1, 2, 1, 1);
    layout.addWidget(labelCallback,      2, 0, 1, 1);
    layout.addWidget(textCallback,       2, 1, 1, 2);
    layout.addWidget(labelEncryptKey,    3, 0, 1, 1);
    layout.addWidget(textlineEncryptKey, 3, 1, 1, 1);
    layout.addWidget(buttonEncryptKey,   3, 2, 1, 1);
    layout.addWidget(labelMaxPacket,     4, 0, 1, 1);
    layout.addWidget(spinMaxPacket,      4, 1, 1, 2);
    layout.addWidget(spacer2,            5, 0, 1, 3);

    let container = form.create_container();
    container.put("host_bind",          comboHostBind);
    container.put("port_bind",          spinPortBind);
    container.put("callback_addresses", textCallback);
    container.put("encrypt_key",        textlineEncryptKey);
    container.put("max_packet_size",    spinMaxPacket);

    let panel = form.create_panel();
    panel.setLayout(layout);

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 600,
        ui_width: 650
    }
}
