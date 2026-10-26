//! Passing one file descriptor over a Unix socket with SCM_RIGHTS.

use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::time::Duration;

use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};
use tokio::io::Interest;
use tokio::net::UnixStream;

/// Data byte carried alongside the descriptor; stream sockets need at least
/// one byte of payload for the control message to be delivered.
const MARKER: u8 = 0x46;

/// Control buffer capacity on receive. Larger than one so that a peer sending
/// several descriptors is reported as `TooManyFds` rather than `Truncated`.
const RECV_FD_CAPACITY: usize = 8;

/// Failure to send or receive a descriptor.
#[derive(Debug, thiserror::Error)]
pub enum FdPassError {
    /// The operation did not complete within the timeout.
    #[error("fd passing timed out")]
    Timeout,
    /// The socket call failed.
    #[error("fd passing socket error: {0}")]
    Io(#[from] io::Error),
    /// The peer closed the connection before a descriptor arrived.
    #[error("peer closed the socket before sending a file descriptor")]
    Closed,
    /// Data arrived without an SCM_RIGHTS control message.
    #[error("message carried no file descriptor")]
    NoFd,
    /// More than one descriptor arrived; all of them were closed.
    #[error("expected one file descriptor, received {0}")]
    TooManyFds(usize),
    /// The kernel truncated the control message (MSG_CTRUNC).
    #[error("control message truncated")]
    Truncated,
}

/// Sends `fd` with one marker byte over `sock`.
pub async fn send_fd(
    sock: &UnixStream,
    fd: BorrowedFd<'_>,
    timeout: Duration,
) -> Result<(), FdPassError> {
    let send = sock.async_io(Interest::WRITABLE, || {
        let fds = [fd];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
            return Err(io::Error::other("control buffer too small"));
        }
        let iov = [IoSlice::new(&[MARKER])];
        rustix::net::sendmsg(sock, &iov, &mut control, SendFlags::NOSIGNAL).map_err(io::Error::from)
    });
    tokio::time::timeout(timeout, send)
        .await
        .map_err(|_| FdPassError::Timeout)??;
    Ok(())
}

/// Receives one descriptor sent by [`send_fd`]. The descriptor is
/// close-on-exec.
pub async fn recv_fd(sock: &UnixStream, timeout: Duration) -> Result<OwnedFd, FdPassError> {
    let recv = sock.async_io(Interest::READABLE, || {
        let mut byte = [0u8; 1];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(RECV_FD_CAPACITY))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let mut iov = [IoSliceMut::new(&mut byte)];
        let msg = rustix::net::recvmsg(sock, &mut iov, &mut control, RecvFlags::CMSG_CLOEXEC)
            .map_err(io::Error::from)?;
        let mut fds = Vec::new();
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(received) = message {
                fds.extend(received);
            }
        }
        Ok((msg.bytes, msg.flags, fds))
    });
    let (bytes, flags, mut fds) = tokio::time::timeout(timeout, recv)
        .await
        .map_err(|_| FdPassError::Timeout)??;
    if flags.contains(ReturnFlags::CTRUNC) {
        return Err(FdPassError::Truncated);
    }
    match fds.len() {
        0 if bytes == 0 => Err(FdPassError::Closed),
        0 => Err(FdPassError::NoFd),
        1 => fds.pop().ok_or(FdPassError::NoFd),
        n => Err(FdPassError::TooManyFds(n)),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write as _;
    use std::os::fd::AsFd;

    use tokio::io::AsyncWriteExt;

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(1);

    #[tokio::test]
    async fn round_trip_passes_a_writable_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let file = File::options().write(true).open(tmp.path()).unwrap();
        let (a, b) = UnixStream::pair().unwrap();

        send_fd(&a, file.as_fd(), TIMEOUT).await.unwrap();
        let received = recv_fd(&b, TIMEOUT).await.unwrap();

        let flags = rustix::io::fcntl_getfd(&received).unwrap();
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
        drop(file);
        let mut via_fd = File::from(received);
        via_fd.write_all(b"through the socket").unwrap();
        drop(via_fd);
        assert_eq!(
            std::fs::read_to_string(tmp.path()).unwrap(),
            "through the socket"
        );
    }

    #[tokio::test]
    async fn recv_times_out_without_data() {
        let (_a, b) = UnixStream::pair().unwrap();
        let err = recv_fd(&b, Duration::from_millis(50)).await.unwrap_err();
        assert!(matches!(err, FdPassError::Timeout), "{err:?}");
    }

    #[tokio::test]
    async fn recv_reports_closed_peer() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(a);
        let err = recv_fd(&b, TIMEOUT).await.unwrap_err();
        assert!(matches!(err, FdPassError::Closed), "{err:?}");
    }

    #[tokio::test]
    async fn recv_reports_plain_byte_without_fd() {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(&[MARKER]).await.unwrap();
        let err = recv_fd(&b, TIMEOUT).await.unwrap_err();
        assert!(matches!(err, FdPassError::NoFd), "{err:?}");
    }

    #[tokio::test]
    async fn recv_rejects_more_than_one_fd() {
        let one = tempfile::tempfile().unwrap();
        let two = tempfile::tempfile().unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        let fds = [one.as_fd(), two.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        assert!(control.push(SendAncillaryMessage::ScmRights(&fds)));
        rustix::net::sendmsg(
            &a,
            &[IoSlice::new(&[MARKER])],
            &mut control,
            SendFlags::empty(),
        )
        .unwrap();

        let err = recv_fd(&b, TIMEOUT).await.unwrap_err();
        assert!(matches!(err, FdPassError::TooManyFds(2)), "{err:?}");
    }
}
