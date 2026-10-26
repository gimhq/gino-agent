//! Guest-side probes, built as a static binary and run inside the microVM.
//!
//! ```text
//! spike-guest vsock-rtt PORT COUNT   # COUNT 64-byte echoes to the host over AF_VSOCK
//! spike-guest tcp ADDR LINE          # one TCP request/response
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::Instant;

const VMADDR_CID_HOST: u32 = 2;

fn vsock_connect(port: u32) -> std::io::Result<UnixStream> {
    // SAFETY: plain socket syscalls on a zeroed sockaddr_vm; the fd is owned by the
    // returned stream (a connected stream socket supports read/write like a Unix one).
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = VMADDR_CID_HOST;
        addr.svm_port = port;
        let ret = libc::connect(
            fd,
            (&raw const addr).cast(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        );
        let stream = UnixStream::from_raw_fd(fd);
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(stream)
    }
}

fn vsock_rtt(port: u32, count: usize) -> std::io::Result<()> {
    let connect = Instant::now();
    let mut conn = vsock_connect(port)?;
    let connect_us = connect.elapsed().as_micros();
    let msg = [0x5au8; 64];
    let mut buf = [0u8; 64];
    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        let t = Instant::now();
        conn.write_all(&msg)?;
        conn.read_exact(&mut buf)?;
        samples.push(t.elapsed().as_micros());
        if buf != msg {
            return Err(std::io::Error::other("echo mismatch"));
        }
    }
    samples.sort_unstable();
    let pct = |p: usize| samples[(samples.len() - 1) * p / 100];
    println!(
        "VSOCK-RTT n={count} connect_us={connect_us} min_us={} median_us={} p90_us={} max_us={}",
        samples[0],
        pct(50),
        pct(90),
        samples[samples.len() - 1]
    );
    Ok(())
}

fn tcp(addr: &str, line: &str) -> std::io::Result<()> {
    let t = Instant::now();
    let mut conn = TcpStream::connect(addr)?;
    conn.write_all(format!("{line}\n").as_bytes())?;
    let mut reply = String::new();
    BufReader::new(conn).read_line(&mut reply)?;
    println!(
        "TCP-REPLY {:?} in {}us",
        reply.trim_end(),
        t.elapsed().as_micros()
    );
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["vsock-rtt", port, count] => match (port.parse(), count.parse()) {
            (Ok(port), Ok(count)) if count > 0 => vsock_rtt(port, count),
            _ => Err(std::io::Error::other("bad vsock-rtt arguments")),
        },
        ["tcp", addr, line] => tcp(addr, line),
        _ => Err(std::io::Error::other(
            "usage: spike-guest vsock-rtt PORT COUNT | tcp ADDR LINE",
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            println!("spike-guest: {err}");
            ExitCode::FAILURE
        }
    }
}
