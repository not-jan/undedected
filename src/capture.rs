use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
    time::Duration,
};

use anyhow::Result;
use futures::{stream::FuturesUnordered, Stream, StreamExt};

use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

fn channels_in_range(s: &str) -> Result<u8, String> {
    match s.parse::<u8>() {
        Ok(0) => Err("must be greater than 0".to_string()),
        Ok(n) if n > 10 => Err("DECT only supports up to 10 channels".to_string()),
        Ok(n) => Ok(n),
        _ => Err("Invalid channel number".to_string()),
    }
}

#[derive(Debug, clap::Args)]
pub struct Args {
    /// How many channels to capture.
    #[clap(short, long, default_value = "1", value_parser = channels_in_range)]
    channels: u8,
    /// The file prefix to use for the captured files.
    #[clap(long, default_value = "dect_dump_")]
    prefix: String,
    /// How long to capture for in seconds.
    #[clap(short, long, default_value = "60")]
    duration: u64,
}

pub trait DataSource {
    /// Receive a single packet. The size of the packet is defined by the underlying data source.
    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>>> + Send + Sync;
    /// Turn this data source into a stream of packets.
    fn into_stream(self) -> impl Stream<Item = Result<Vec<u8>>> + Unpin;
}

#[derive(Debug)]
pub struct UdpChannel {
    #[allow(dead_code)]
    /// The index of the channel.
    /// This is currently unused as the script that we use to capture DECT is broken.
    index: usize,
    socket: UdpSocket,
}

impl UdpChannel {
    /// The size of the buffer used to receive packets.
    const BUFFER_SIZE: usize = 2048;

    /// Create a new data source that listens on the given port for UDP packets.
    pub async fn new(port: u16, index: usize) -> Result<Self> {
        let addr = Ipv4Addr::new(0, 0, 0, 0);
        let addr = SocketAddrV4::new(addr, port);

        let socket = UdpSocket::bind(addr).await?;

        Ok(Self { index, socket })
    }
}

pub struct FileChannel {
    file: File,
}

impl FileChannel {
    /// The size of the buffer used to receive packets.
    const BUFFER_SIZE: usize = 2048;

    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path).await?;
        Ok(Self { file })
    }
}

impl DataSource for FileChannel {
    async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut buf = [0u8; Self::BUFFER_SIZE];
        let size = self.file.read(&mut buf).await?;
        if size > 0 {
            Ok(buf[..size].to_vec())
        } else {
            Ok(vec![])
        }
    }

    fn into_stream(self) -> impl Stream<Item = Result<Vec<u8>>> + Unpin {
        futures::stream::try_unfold(self, |mut this| async move {
            let buffer = this.recv().await?;
            Ok(Some((buffer, this)))
        })
        .filter_map(|buffer| async move {
            match buffer {
                // When the file is empty, we return None.
                Ok(buffer) if buffer.is_empty() => None,
                Ok(buffer) => Some(Ok(buffer)),
                Err(e) => Some(Err(e)),
            }
        })
        // After the file is empty, we return None forever.
        .fuse()
        .boxed()
    }
}

impl DataSource for UdpChannel {
    async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut buf = [0u8; Self::BUFFER_SIZE];
        let size = self.socket.recv(&mut buf).await?;
        if size > 0 {
            Ok(buf[..size].to_vec())
        } else {
            Ok(vec![])
        }
    }

    fn into_stream(self) -> impl Stream<Item = Result<Vec<u8>>> + Unpin {
        futures::stream::try_unfold(self, |mut this| async move {
            let buffer = this.recv().await?;
            Ok(Some((buffer, this)))
        })
        .filter(move |buffer| {
            let result = match buffer {
                // Filter out empty buffers.
                Ok(buffer) => !buffer.is_empty(),
                Err(_) => true,
            };
            async move { result }
        })
        .boxed()
    }
}

pub async fn run(args: Args) -> Result<()> {
    let token = CancellationToken::new();

    (0..args.channels)
        .map(|index| {
            let path = format!("{}{}.bin", &args.prefix, index);
            let token = token.clone();

            async move {
                let channel = UdpChannel::new(2323 + (index as u16), index as usize).await?;

                let mut file = File::open(path).await?;

                let fut = async move {
                    let mut stream = channel.into_stream();

                    while let Some(packet) = stream.next().await {
                        let packet = packet?;
                        file.write_all(&packet).await?;
                    }

                    Ok::<(), anyhow::Error>(())
                };

                let handle = tokio::spawn(async move {
                    let result = token.run_until_cancelled(fut).await;
                    match result {
                        Some(Ok(())) => Ok(()),
                        Some(Err(e)) => Err(e),
                        None => Ok(()),
                    }
                });

                Ok(handle)
            }
        })
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>>>()?;

    let duration = tokio::time::sleep(Duration::from_secs(args.duration));

    tokio::select! {
        _ = duration => {
            println!("Capture duration reached, exiting...");
        },
        _ = tokio::signal::ctrl_c() => {
            println!("Ctrl-C received, exiting...");
        },
    }

    token.cancel();

    Ok(())
}
