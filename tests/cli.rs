use std::net::TcpListener;

#[test]
fn run_emits_json_for_a_scan() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let output = crusty_guard::run([
        "crusty-guard",
        "--host",
        "127.0.0.1",
        "--ports",
        &port.to_string(),
        "--format",
        "json",
    ])
    .unwrap();

    assert!(output.contains("\"target\":\"127.0.0.1\""));
    assert!(output.contains(&format!("\"scanned_ports\":[{port}]")));
}
