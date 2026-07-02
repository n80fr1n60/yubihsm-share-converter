use assert_cmd::Command;

fn fixture(name: &str) -> Vec<u8> {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/data");
    path.push(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("missing fixture {path:?}: {e}"))
}

fn run_gen_fixture(args: &[&str]) -> Vec<u8> {
    let assert = Command::cargo_bin("gen_fixture")
        .expect("gen_fixture binary")
        .args(args)
        .assert()
        .success();
    assert.get_output().stdout.clone()
}

#[test]
fn gen_fixture_outputs_match_committed_fixtures() {
    for (args, expected_file) in [
        (&[][..], "toy_2of3.txt"),
        (&["--key-len=16"][..], "toy_2of3_aes128.txt"),
        (&["--key-len=24"][..], "toy_2of3_aes192.txt"),
        (&["--key-len=32"][..], "toy_2of3.txt"),
    ] {
        let got = run_gen_fixture(args);
        let expected = fixture(expected_file);
        assert_eq!(
            got, expected,
            "gen_fixture {args:?} must reproduce {expected_file} byte-for-byte"
        );
    }
}

#[test]
fn gen_fixture_rejects_unknown_key_length_argument() {
    Command::cargo_bin("gen_fixture")
        .expect("gen_fixture binary")
        .arg("--key-len=12")
        .assert()
        .failure();
}
