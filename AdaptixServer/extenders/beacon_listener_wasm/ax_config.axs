/// Beacon WASM listener

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
    spinPortBind.setValue(8080);
    spinPortBind.setEnabled(mode_create)

    let labelCallback = form.create_label("Callback addresses:");
    let textCallback = form.create_list();
    textCallback.setButtonsEnabled(true);
    textCallback.addItem("address:port");

    let labelWsEndpoint = form.create_label("WebSocket endpoint:");
    let textlineWsEndpoint = form.create_textline("/ws");

    let labelWasmEndpoint = form.create_label("WASM serve endpoint:");
    let textlineWasmEndpoint = form.create_textline("/app.wasm");

    let labelEncryptKey = form.create_label("Encryption key:");
    let textlineEncryptKey = form.create_textline(ax.random_string(32, "hex"));
    textlineEncryptKey.setEnabled(mode_create)
    let buttonEncryptKey = form.create_button("Generate");
    buttonEncryptKey.setEnabled(mode_create)

    let certSelector = form.create_selector_file();
    certSelector.setPlaceholder("SSL Certificate (optional, auto-generate if empty)");
    let keySelector = form.create_selector_file();
    keySelector.setPlaceholder("SSL Key (optional, auto-generate if empty)");
    let layout_group = form.create_vlayout();
    layout_group.addWidget(certSelector);
    layout_group.addWidget(keySelector);
    let panel_group = form.create_panel();
    panel_group.setLayout(layout_group);
    let ssl_group = form.create_groupbox("Use SSL", true)
    ssl_group.setPanel(panel_group);
    ssl_group.setChecked(false);

    form.connect(buttonEncryptKey, "clicked", function() { textlineEncryptKey.setText( ax.random_string(32, "hex") ); });

    let layoutMain = form.create_gridlayout();
    layoutMain.addWidget(labelHost,            0, 0, 1, 1);
    layoutMain.addWidget(comboHostBind,        0, 1, 1, 1);
    layoutMain.addWidget(spinPortBind,         0, 2, 1, 1);
    layoutMain.addWidget(labelCallback,        1, 0, 1, 1);
    layoutMain.addWidget(textCallback,         1, 1, 1, 2);
    layoutMain.addWidget(labelWsEndpoint,      2, 0, 1, 1);
    layoutMain.addWidget(textlineWsEndpoint,   2, 1, 1, 2);
    layoutMain.addWidget(labelWasmEndpoint,    3, 0, 1, 1);
    layoutMain.addWidget(textlineWasmEndpoint, 3, 1, 1, 2);
    layoutMain.addWidget(labelEncryptKey,      4, 0, 1, 1);
    layoutMain.addWidget(textlineEncryptKey,   4, 1, 1, 1);
    layoutMain.addWidget(buttonEncryptKey,     4, 2, 1, 1);
    layoutMain.addWidget(ssl_group,            5, 0, 1, 3);

    let panelMain = form.create_panel();
    panelMain.setLayout(layoutMain);

    // LOADER PAGE
    let textLoaderPage = form.create_textmulti("<!DOCTYPE html>\n<html>\n<head><title>App</title></head>\n<body>\n<script>\nconst go = new Go();\nWebAssembly.instantiateStreaming(fetch('/app.wasm'), go.importObject).then((result) => {\n    go.run(result.instance);\n});\n</script>\n</body>\n</html>");

    let layoutLoader = form.create_gridlayout();
    layoutLoader.addWidget(textLoaderPage, 0, 0, 1, 1);

    let panelLoader = form.create_panel();
    panelLoader.setLayout(layoutLoader);

    //
    let tabs = form.create_tabs();
    tabs.addTab(panelMain, "Main settings");
    tabs.addTab(panelLoader, "Loader Page");

    let layout = form.create_hlayout();
    layout.addWidget(tabs);

    let container = form.create_container();
    container.put("host_bind",          comboHostBind);
    container.put("port_bind",          spinPortBind);
    container.put("callback_addresses", textCallback);
    container.put("ws_endpoint",        textlineWsEndpoint);
    container.put("wasm_endpoint",      textlineWasmEndpoint);
    container.put("encrypt_key",        textlineEncryptKey);
    container.put("ssl",                ssl_group);
    container.put("ssl_cert",           certSelector);
    container.put("ssl_key",            keySelector);
    container.put("loader_page",        textLoaderPage);

    let panel = form.create_panel();
    panel.setLayout(layout);

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 700,
        ui_width: 750
    }
}
