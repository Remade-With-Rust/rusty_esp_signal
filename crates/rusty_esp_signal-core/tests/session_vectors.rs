//! enc-ble M1: one complete setup session, computed by the independent
//! Python oracle (`tools/setup_golden.py`: its own P-256, PBKDF2, HKDF,
//! RFC 6979 ECDSA and ChaCha20-Poly1305, each checked against its RFC),
//! reproduced byte for byte by `rusty_esp_signal_core::setup` from both
//! halves, with the device's signature made by mID's `DeviceKey`. Then the
//! refusals: a wrong code, the wrong device, another carrier.

use rusty_esp_core::error::Error;
use rusty_esp_signal_core::mid::key::DeviceKey;
use rusty_esp_signal_core::mid::signer::DeviceSigner;
use rusty_esp_signal_core::setup::{
    Code, Context, DEVPUB_LEN, Prover, SALT_LEN, Secrets, TAG_LEN, VERSION, Verifier,
    reply_prehash, respond_with_scalar, verify_reply,
};

const FIXTURE: &str = include_str!("fixtures/setup/session-v1.txt");

fn get(key: &str) -> Vec<u8> {
    let line = FIXTURE
        .lines()
        .find(|l| l.split(" = ").next() == Some(key))
        .unwrap_or_else(|| panic!("fixture has no {key}"));
    let hex = line.split(" = ").nth(1).unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(key: &str) -> [u8; N] {
    get(key)
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("{key}: {} bytes, not {N}", v.len()))
}

fn code() -> Code {
    Code::parse(core::str::from_utf8(&get("code_as_typed")).unwrap()).unwrap()
}

fn iterations() -> u32 {
    u32::from_be_bytes(arr("iterations"))
}

fn secrets() -> Secrets {
    Secrets::derive(&code(), &arr::<SALT_LEN>("salt"), iterations()).unwrap()
}

fn context() -> Context {
    Context::new(&get("label"), &arr::<DEVPUB_LEN>("devpub")).unwrap()
}

fn header(kind: u8) -> [u8; 2] {
    [VERSION, kind]
}

#[test]
fn the_code_and_the_verifier() {
    assert_eq!(code().as_bytes()[..], get("pw")[..]);
    let verifier = Verifier::from_secrets(&secrets(), &arr("salt"), iterations());
    assert_eq!(verifier.encode()[..], get("setup_v")[..]);
    // the stored record reads back as the same verifier
    let read = Verifier::decode(&get("setup_v")).unwrap();
    assert_eq!(read.encode()[..], get("setup_v")[..]);
    assert!(read.matches(&secrets()));
    assert_eq!(read.salt()[..], get("salt")[..]);
    assert_eq!(read.iterations(), iterations());
}

#[test]
fn the_context_and_the_device_key() {
    assert_eq!(context().as_bytes(), &get("context")[..]);
    let device = DeviceKey::from_secret(&arr("device_secret"), "setup-test").unwrap();
    assert_eq!(device.did().pubkey()[..], get("devpub")[..]);
}

#[test]
fn a_whole_session_byte_for_byte() {
    let device_key = DeviceKey::from_secret(&arr("device_secret"), "setup-test").unwrap();
    let verifier = Verifier::decode(&get("setup_v")).unwrap();

    // Start: the browser
    let prover = Prover::start_with_scalar(secrets(), context(), &arr("x")).unwrap();
    assert_eq!(prover.share_p()[..], get("shareP")[..]);
    let mut start = vec![VERSION, 0x01, 0x01];
    start.extend_from_slice(prover.share_p());
    assert_eq!(start, get("msg_start"));

    // Reply: the device, signing with its did:mata key
    let response = respond_with_scalar(&verifier, &context(), prover.share_p(), &arr("y")).unwrap();
    assert_eq!(response.share_v()[..], get("shareV")[..]);
    assert_eq!(response.confirm_v()[..], get("confirmV")[..]);
    let prehash = reply_prehash(
        &context(),
        prover.share_p(),
        response.share_v(),
        response.confirm_v(),
    );
    assert_eq!(prehash[..], get("reply_prehash")[..]);
    let sig = device_key.sign_prehash(&prehash);
    assert_eq!(
        sig[..],
        get("reply_sig")[..],
        "mID's RFC 6979 low-s signature"
    );
    let mut reply = vec![VERSION, 0x02];
    reply.extend_from_slice(response.share_v());
    reply.extend_from_slice(response.confirm_v());
    reply.extend_from_slice(&sig);
    assert_eq!(reply, get("msg_reply"));

    // the browser checks the Reply: the device it was shown, the code
    verify_reply(&arr("devpub"), &prehash, &sig).unwrap();
    let (confirm_p, browser) = prover
        .finish(response.share_v(), response.confirm_v())
        .unwrap();
    assert_eq!(confirm_p[..], get("confirmP")[..]);
    let mut confirm = vec![VERSION, 0x03];
    confirm.extend_from_slice(&confirm_p);
    assert_eq!(confirm, get("msg_confirm"));

    // Confirm: the device
    let device = response.confirm(&confirm_p).unwrap();
    let (mut device_send, mut device_recv) = device.split();
    let (mut browser_send, mut browser_recv) = browser.split();

    // Ready, sealed by the device
    let mut buf = [0u8; 512];
    let n = device_send
        .seal(&header(0x04), &get("ready_plain"), &mut buf)
        .unwrap();
    assert_eq!(&buf[..n], &get("msg_ready")[2..]);
    let mut plain = [0u8; 512];
    let m = browser_recv
        .open(&header(0x04), &buf[..n], &mut plain)
        .unwrap();
    assert_eq!(&plain[..m], &get("ready_plain")[..]);

    // Settings, sealed by the browser
    let n = browser_send
        .seal(&header(0x05), &get("settings_plain"), &mut buf)
        .unwrap();
    assert_eq!(&buf[..n], &get("msg_settings")[2..]);
    assert_eq!(n, get("settings_plain").len() + TAG_LEN);
    let m = device_recv
        .open(&header(0x05), &buf[..n], &mut plain)
        .unwrap();
    assert_eq!(&plain[..m], &get("settings_plain")[..]);

    // Result, the device's second sealed message
    let n = device_send
        .seal(&header(0x06), &get("result_plain"), &mut buf)
        .unwrap();
    assert_eq!(&buf[..n], &get("msg_result")[2..]);
    let m = browser_recv
        .open(&header(0x06), &buf[..n], &mut plain)
        .unwrap();
    assert_eq!(&plain[..m], &get("result_plain")[..]);
}

#[test]
fn a_wrong_code_is_refused_on_both_sides() {
    let verifier = Verifier::decode(&get("setup_v")).unwrap();
    let wrong = Secrets::derive(
        &Code::parse("7KXQ3-M9PRV").unwrap(),
        &arr("salt"),
        iterations(),
    )
    .unwrap();
    let prover = Prover::start_with_scalar(wrong, context(), &arr("x")).unwrap();
    let response = respond_with_scalar(&verifier, &context(), prover.share_p(), &arr("y")).unwrap();
    // the browser cannot verify the device's confirmation ...
    let share_v = *response.share_v();
    let confirm_v = *response.confirm_v();
    assert_eq!(
        prover.finish(&share_v, &confirm_v).err(),
        Some(Error::Crypto)
    );
    // ... and a guessed confirmation does not open the device
    assert_eq!(response.confirm(&[0u8; 32]).err(), Some(Error::Crypto));
}

#[test]
fn another_device_or_another_carrier_is_refused() {
    let verifier = Verifier::decode(&get("setup_v")).unwrap();
    // a session the device answers on BLE, which the browser believes is USB
    let usb = Context::new(b"usb", &arr::<DEVPUB_LEN>("devpub")).unwrap();
    let prover = Prover::start_with_scalar(secrets(), usb, &arr("x")).unwrap();
    let response = respond_with_scalar(&verifier, &context(), prover.share_p(), &arr("y")).unwrap();
    let (share_v, confirm_v) = (*response.share_v(), *response.confirm_v());
    assert_eq!(
        prover.finish(&share_v, &confirm_v).err(),
        Some(Error::Crypto)
    );

    // a signature by any other key does not pass for the device's
    let impostor = DeviceKey::from_secret(&[0x42; 32], "impostor").unwrap();
    let prover = Prover::start_with_scalar(secrets(), context(), &arr("x")).unwrap();
    let response = respond_with_scalar(&verifier, &context(), prover.share_p(), &arr("y")).unwrap();
    let prehash = reply_prehash(
        &context(),
        prover.share_p(),
        response.share_v(),
        response.confirm_v(),
    );
    let forged = impostor.sign_prehash(&prehash);
    assert_eq!(
        verify_reply(&arr("devpub"), &prehash, &forged).err(),
        Some(Error::Crypto)
    );
    // the device's own signature over another session's prehash
    let device = DeviceKey::from_secret(&arr("device_secret"), "setup-test").unwrap();
    let mut other = prehash;
    other[0] ^= 1;
    let sig = device.sign_prehash(&other);
    assert_eq!(
        verify_reply(&arr("devpub"), &prehash, &sig).err(),
        Some(Error::Crypto)
    );
}

#[test]
fn shares_that_are_not_points_are_refused() {
    let verifier = Verifier::decode(&get("setup_v")).unwrap();
    let mut bad = arr::<65>("shareP");
    bad[40] ^= 1;
    assert_eq!(
        respond_with_scalar(&verifier, &context(), &bad, &arr("y")).err(),
        Some(Error::InvalidFormat)
    );
    assert_eq!(
        respond_with_scalar(&verifier, &context(), &get("shareP")[..33], &arr("y")).err(),
        Some(Error::InvalidFormat)
    );
    let prover = Prover::start_with_scalar(secrets(), context(), &arr("x")).unwrap();
    let mut bad_v = arr::<65>("shareV");
    bad_v[1] ^= 0x80;
    assert_eq!(
        prover.finish(&bad_v, &arr::<32>("confirmV")).err(),
        Some(Error::InvalidFormat)
    );
}

#[test]
fn records_that_are_refused() {
    let good = get("setup_v");
    assert!(Verifier::decode(&good[..117]).is_err());
    let mut v = good.clone();
    v[0] = 2;
    assert_eq!(Verifier::decode(&v).err(), Some(Error::InvalidFormat));
    let mut v = good.clone();
    v[1..33].fill(0);
    assert_eq!(
        Verifier::decode(&v).err(),
        Some(Error::InvalidFormat),
        "w0 = 0"
    );
    let mut v = good.clone();
    v[1..33].fill(0xFF);
    assert_eq!(
        Verifier::decode(&v).err(),
        Some(Error::InvalidFormat),
        "w0 >= n"
    );
    let mut v = good.clone();
    v[60] ^= 1;
    assert_eq!(
        Verifier::decode(&v).err(),
        Some(Error::InvalidFormat),
        "L off the curve"
    );
    let mut v = good;
    v[114..118].copy_from_slice(&999u32.to_be_bytes());
    assert_eq!(
        Verifier::decode(&v).err(),
        Some(Error::InvalidFormat),
        "too few iterations"
    );
    assert_eq!(
        Secrets::derive(&code(), &arr("salt"), 999).err(),
        Some(Error::InvalidFormat)
    );
}
