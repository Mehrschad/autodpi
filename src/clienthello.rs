//! Minimal TLS ClientHello construction and parsing.
//!
//! We deliberately avoid pulling in a full TLS stack here. The probe only needs
//! a *well-formed* ClientHello that carries an SNI extension so that:
//!   1. real servers reply with a ServerHello (proving the bytes got through), and
//!   2. stateful DPI can read the SNI and decide whether to block the flow.
//!
//! The forwarder, by contrast, never builds a ClientHello — it forwards the
//! *real* one produced by the user's client (xray/v2ray/browser). For that path
//! we only need [`find_sni_split_offset`] to know where to cut the byte stream.

/// Build a TLS 1.2 ClientHello record carrying the given SNI hostname.
///
/// The returned bytes are a complete TLS record (handshake content type 0x16)
/// ready to be written to a TCP stream.
pub fn build_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();

    // ---- server_name extension (0x0000) ----
    let mut server_name = Vec::new();
    server_name.push(0x00); // name_type = host_name
    server_name.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    server_name.extend_from_slice(sni_bytes);

    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type: server_name
    sni_ext.extend_from_slice(&((server_name.len() + 2) as u16).to_be_bytes()); // ext data len
    sni_ext.extend_from_slice(&(server_name.len() as u16).to_be_bytes()); // server_name_list len
    sni_ext.extend_from_slice(&server_name);

    // ---- supported_groups (0x000a) ----
    let groups: [u16; 3] = [0x001d, 0x0017, 0x0018]; // x25519, secp256r1, secp384r1
    let mut sg_ext = Vec::new();
    sg_ext.extend_from_slice(&0x000au16.to_be_bytes());
    sg_ext.extend_from_slice(&((groups.len() * 2 + 2) as u16).to_be_bytes());
    sg_ext.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for g in groups {
        sg_ext.extend_from_slice(&g.to_be_bytes());
    }

    // ---- ec_point_formats (0x000b) ----
    let mut ecp_ext = Vec::new();
    ecp_ext.extend_from_slice(&0x000bu16.to_be_bytes());
    ecp_ext.extend_from_slice(&0x0002u16.to_be_bytes()); // ext data len
    ecp_ext.push(0x01); // list len
    ecp_ext.push(0x00); // uncompressed

    // ---- signature_algorithms (0x000d) ----
    let sigs: [u16; 8] = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    let mut sig_ext = Vec::new();
    sig_ext.extend_from_slice(&0x000du16.to_be_bytes());
    sig_ext.extend_from_slice(&((sigs.len() * 2 + 2) as u16).to_be_bytes());
    sig_ext.extend_from_slice(&((sigs.len() * 2) as u16).to_be_bytes());
    for s in sigs {
        sig_ext.extend_from_slice(&s.to_be_bytes());
    }

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);
    extensions.extend_from_slice(&sg_ext);
    extensions.extend_from_slice(&ecp_ext);
    extensions.extend_from_slice(&sig_ext);

    // ---- ClientHello body ----
    let ciphers: [u16; 10] = [
        0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0x009c, 0x009d, 0x002f, 0x0035,
    ];
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // client_version = TLS 1.2
    body.extend_from_slice(&client_random()); // 32-byte random
    body.push(0x00); // session_id length = 0
    body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for c in ciphers {
        body.extend_from_slice(&c.to_be_bytes());
    }
    body.push(0x01); // compression methods length
    body.push(0x00); // null compression
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    // ---- handshake header ----
    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(0x01); // ClientHello
    let blen = body.len();
    handshake.push((blen >> 16) as u8);
    handshake.push((blen >> 8) as u8);
    handshake.push(blen as u8);
    handshake.extend_from_slice(&body);

    // ---- TLS record header ----
    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(0x16); // handshake
    record.extend_from_slice(&0x0301u16.to_be_bytes()); // record version TLS 1.0 (broad compat)
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Cheap, dependency-free 32 bytes of pseudo-randomness for the ClientHello
/// random field. Quality is irrelevant to the probe; we only want flows that do
/// not all look byte-identical to a passive observer.
fn client_random() -> [u8; 32] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15)
        ^ (std::process::id() as u64).wrapping_mul(0x2545F4914F6CDD1D);
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        // xorshift64*
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        let v = seed.wrapping_mul(0x2545F4914F6CDD1D);
        let bytes = v.to_le_bytes();
        for (i, b) in chunk.iter_mut().enumerate() {
            *b = bytes[i];
        }
    }
    out
}

/// Given the first bytes of a real client's traffic (expected to be a TLS
/// ClientHello), locate a good byte offset to split the stream *inside* the SNI
/// hostname, so that no single TCP segment contains the full SNI string.
///
/// Returns `None` if the buffer does not look like a ClientHello with an SNI.
pub fn find_sni_split_offset(buf: &[u8]) -> Option<usize> {
    // TLS record header: type(1) version(2) length(2)
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    // Handshake header begins at offset 5: type(1) length(3)
    let mut p = 5usize;
    if buf.len() < p + 4 || buf[p] != 0x01 {
        return None;
    }
    p += 4; // skip handshake type + length
    // client_version(2) + random(32)
    p += 2 + 32;
    if buf.len() < p + 1 {
        return None;
    }
    // session_id
    let sid_len = buf[p] as usize;
    p += 1 + sid_len;
    if buf.len() < p + 2 {
        return None;
    }
    // cipher_suites
    let cs_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2 + cs_len;
    if buf.len() < p + 1 {
        return None;
    }
    // compression_methods
    let cm_len = buf[p] as usize;
    p += 1 + cm_len;
    if buf.len() < p + 2 {
        return None;
    }
    // extensions
    let ext_total = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(buf.len());
    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let ext_len = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
        let ext_body = p + 4;
        if ext_type == 0x0000 {
            // server_name extension: list_len(2) name_type(1) name_len(2) name...
            if ext_body + 5 <= buf.len() {
                let name_len = u16::from_be_bytes([buf[ext_body + 3], buf[ext_body + 4]]) as usize;
                let name_start = ext_body + 5;
                if name_start + name_len <= buf.len() && name_len >= 2 {
                    // Split in the middle of the hostname so neither half is whole.
                    return Some(name_start + name_len / 2);
                }
            }
            return None;
        }
        p = ext_body + ext_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_is_a_wellformed_record() {
        let ch = build_client_hello("example.com");
        // record header
        assert_eq!(ch[0], 0x16, "content type must be handshake");
        let rec_len = u16::from_be_bytes([ch[3], ch[4]]) as usize;
        assert_eq!(rec_len, ch.len() - 5, "record length must match payload");
        // handshake header
        assert_eq!(ch[5], 0x01, "handshake type must be ClientHello");
        let hs_len = ((ch[6] as usize) << 16) | ((ch[7] as usize) << 8) | ch[8] as usize;
        assert_eq!(hs_len, ch.len() - 9, "handshake length must match body");
    }

    #[test]
    fn sni_offset_lands_inside_hostname() {
        let host = "blocked.example.org";
        let ch = build_client_hello(host);
        let off = find_sni_split_offset(&ch).expect("should locate SNI");
        // The byte at the offset must be part of the hostname.
        let hpos = ch
            .windows(host.len())
            .position(|w| w == host.as_bytes())
            .expect("hostname present in hello");
        assert!(off > hpos && off < hpos + host.len(), "offset inside SNI");
    }

    #[test]
    fn random_field_varies_between_hellos() {
        let a = build_client_hello("x.com");
        let b = build_client_hello("x.com");
        // random occupies bytes 11..43 (5 record + 4 hs + 2 version)
        assert_ne!(&a[11..43], &b[11..43], "client random should differ");
    }

    #[test]
    fn non_clienthello_has_no_sni_offset() {
        assert_eq!(find_sni_split_offset(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]), None);
        assert_eq!(find_sni_split_offset(&[]), None);
    }
}
