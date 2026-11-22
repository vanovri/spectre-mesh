#[cfg(target_os = "linux")]
mod linux_tests {
    use std::collections::HashSet;
    use std::io::{BufRead, BufReader, Write};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use spectre_tls::{discover_pid_tls_targets, resolve_go_tls_probes, TlsInterceptor};
    use spectre_xdp::L7RawChunkEvent;

    static LIVE_TLS_LOCK: Mutex<()> = Mutex::new(());

    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
    }

    fn temp_work_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("spectre_m04_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn drain_until_done(
        interceptor: Arc<Mutex<TlsInterceptor>>,
        stop: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<Vec<L7RawChunkEvent>> {
        std::thread::spawn(move || {
            let mut collected = Vec::new();
            while !stop.load(Ordering::Acquire) {
                {
                    let mut guard = interceptor.lock().unwrap();
                    collected.extend(guard.drain_tls_events());
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            // Final flush after child exit
            std::thread::sleep(std::time::Duration::from_millis(30));
            let mut guard = interceptor.lock().unwrap();
            collected.extend(guard.drain_tls_events());
            collected.sort_by_key(|e| (e.ts_ns, e.chunk_seq));
            collected
        })
    }

    fn objdump_ret_offsets(bin: &Path, func_symbol: &str, entry_file_off: u64) -> Vec<u64> {
        let out = Command::new("objdump")
            .arg("-d")
            .arg(bin)
            .output()
            .expect("objdump -d");
        assert!(out.status.success());
        let txt = String::from_utf8_lossy(&out.stdout);
        let needle = format!("<{func_symbol}>:");
        let mut in_func = false;
        let mut first_vaddr: Option<u64> = None;
        let mut rets = Vec::new();
        for line in txt.lines() {
            if line.contains(&needle) {
                in_func = true;
                let hex_part = line.split_whitespace().next().unwrap_or("0");
                first_vaddr = u64::from_str_radix(hex_part, 16).ok();
                continue;
            }
            if in_func {
                if line.trim().is_empty() || (line.ends_with(">:") && !line.starts_with(' ')) {
                    break;
                }
                if let Some((addr_str, rest)) = line.split_once(':') {
                    let tokens: Vec<&str> = rest.split_whitespace().collect();
                    if tokens
                        .iter()
                        .any(|&t| t == "ret" || t == "retq" || t == "repz")
                        && rest.contains("ret")
                    {
                        if let (Some(base), Ok(va)) =
                            (first_vaddr, u64::from_str_radix(addr_str.trim(), 16))
                        {
                            rets.push(entry_file_off + (va - base));
                        }
                    }
                }
            }
        }
        rets
    }

    #[test]
    fn live_openssl_tls13_1000_requests_including_gt_16kb_zero_fd_leak() {
        let _guard = LIVE_TLS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = temp_work_dir("openssl");
        let src = dir.join("openssl_echo.c");
        let bin = dir.join("openssl_echo");

        let c_code = r#"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void write_exact_ssl(SSL *ssl, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 24576) chunk = 24576;
        int w = SSL_write(ssl, buf + off, (int)chunk);
        if (w <= 0) exit(21);
        off += (size_t)w;
    }
}

static void read_exact_ssl(SSL *ssl, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int r = SSL_read(ssl, buf + off, (int)(len - off));
        if (r <= 0) exit(22);
        off += (size_t)r;
    }
}

typedef struct {
    SSL_CTX *srv_ctx;
    int listen_fd;
} srv_args_t;

static void *server_thread(void *arg) {
    srv_args_t *sa = (srv_args_t *)arg;
    int cfd = accept(sa->listen_fd, NULL, NULL);
    if (cfd < 0) exit(23);
    int nodelay = 1;
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    SSL *ssl = SSL_new(sa->srv_ctx);
    SSL_set_fd(ssl, cfd);
    if (SSL_accept(ssl) != 1) exit(24);

    uint8_t *buf = malloc(32768);
    for (int i = 0; i < 1000; i++) {
        uint32_t net_len = 0;
        read_exact_ssl(ssl, (uint8_t *)&net_len, 4);
        uint32_t plen = ntohl(net_len);
        if (plen > 32768) exit(25);
        read_exact_ssl(ssl, buf, plen);
        /* Echo back with RSP tag prefix */
        buf[0] = 'R';
        buf[1] = 'S';
        buf[2] = 'P';
        write_exact_ssl(ssl, (const uint8_t *)&net_len, 4);
        write_exact_ssl(ssl, buf, plen);
    }
    free(buf);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(cfd);
    return NULL;
}

static void gen_cert(EVP_PKEY **out_key, X509 **out_cert) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    X509 *x = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), 3600);
    X509_set_pubkey(x, pkey);
    X509_NAME *name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
    X509_set_issuer_name(x, name);
    X509_sign(x, pkey, EVP_sha256());

    *out_key = pkey;
    *out_cert = x;
}

int main(void) {
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    gen_cert(&pkey, &cert);

    SSL_CTX *srv_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX *cli_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(srv_ctx, TLS1_3_VERSION);
    SSL_CTX_set_min_proto_version(cli_ctx, TLS1_3_VERSION);
    SSL_CTX_use_certificate(srv_ctx, cert);
    SSL_CTX_use_PrivateKey(srv_ctx, pkey);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) exit(26);
    if (listen(lfd, 8) != 0) exit(27);
    socklen_t alen = sizeof(addr);
    getsockname(lfd, (struct sockaddr *)&addr, &alen);

    /* Barrier: wait until SpectreMesh attaches uprobes via /proc/<pid>/maps */
    printf("READY %d\n", ntohs(addr.sin_port));
    fflush(stdout);
    char go[8];
    if (!fgets(go, sizeof(go), stdin)) exit(28);

    pthread_t th;
    srv_args_t sa = { .srv_ctx = srv_ctx, .listen_fd = lfd };
    pthread_create(&th, NULL, server_thread, &sa);

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) exit(29);
    int nodelay = 1;
    setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    SSL *cli = SSL_new(cli_ctx);
    SSL_set_fd(cli, sfd);
    if (SSL_connect(cli) != 1) exit(30);

    uint8_t *tx = malloc(32768);
    uint8_t *rx = malloc(32768);
    for (int i = 0; i < 1000; i++) {
        uint32_t plen = (i % 50 == 0) ? 20480 : 128; /* > 16 KB payloads every 50 reqs */
        memset(tx, 'A' + (i % 26), plen);
        snprintf((char *)tx, plen, "REQ|%04d|LEN=%u|END|", i, plen);
        tx[plen - 4] = 'T';
        tx[plen - 3] = 'A';
        tx[plen - 2] = 'I';
        tx[plen - 1] = 'L';

        uint32_t net_len = htonl(plen);
        write_exact_ssl(cli, (const uint8_t *)&net_len, 4);
        write_exact_ssl(cli, tx, plen);

        uint32_t rnet = 0;
        read_exact_ssl(cli, (uint8_t *)&rnet, 4);
        uint32_t rlen = ntohl(rnet);
        if (rlen != plen) exit(31);
        read_exact_ssl(cli, rx, rlen);
    }

    free(tx);
    free(rx);
    SSL_shutdown(cli);
    SSL_free(cli);
    close(sfd);
    pthread_join(th, NULL);
    close(lfd);
    SSL_CTX_free(srv_ctx);
    SSL_CTX_free(cli_ctx);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return 0;
}
"#;
        std::fs::write(&src, c_code).unwrap();
        let compile = Command::new("gcc")
            .args(["-O2", "-pthread"])
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .args(["-lssl", "-lcrypto"])
            .output()
            .expect("gcc OpenSSL helper");
        assert!(
            compile.status.success(),
            "gcc failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );

        let fds_before = open_fd_count();
        {
            let oss_bpf = std::fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../probes/build/tls_openssl.bpf.o"),
            )
            .unwrap();
            let go_bpf = std::fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../probes/build/tls_go.bpf.o"),
            )
            .unwrap();

            let interceptor = Arc::new(Mutex::new(
                TlsInterceptor::load(&oss_bpf, &go_bpf).expect("load TLS BPF probes"),
            ));

            let mut child = Command::new(&bin)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("spawn openssl_echo");

            let child_pid = child.id();
            let mut stdout_reader = BufReader::new(child.stdout.take().unwrap());
            let mut ready_line = String::new();
            stdout_reader.read_line(&mut ready_line).unwrap();
            assert!(ready_line.starts_with("READY "), "got {ready_line}");

            let summary = interceptor.lock().unwrap().attach_pid(child_pid).unwrap();
            assert!(
                summary.openssl_probes_attached >= 4,
                "expected OpenSSL uprobes attached, got {summary:?}"
            );

            let stop = Arc::new(AtomicBool::new(false));
            let drainer = drain_until_done(Arc::clone(&interceptor), Arc::clone(&stop));

            {
                let mut stdin = child.stdin.take().unwrap();
                writeln!(stdin, "GO").unwrap();
                stdin.flush().unwrap();
            }

            let status = child.wait().expect("wait openssl_echo");
            stop.store(true, Ordering::Release);
            let events = drainer.join().unwrap();
            assert!(status.success(), "openssl_echo exited with {status}");
            let drops = interceptor.lock().unwrap().read_ringbuf_drops().unwrap();
            assert_eq!(drops, 0, "expected 0 RingBuf drops in OpenSSL probe");

            // Reconstruct continuous plaintext streams per (conn_ptr, direction)
            let mut streams: std::collections::HashMap<(u64, u8), Vec<u8>> =
                std::collections::HashMap::new();
            let mut saw_positive_fd = false;
            for ev in &events {
                if ev.tls_source == 1 {
                    if ev.fd > 2 {
                        saw_positive_fd = true;
                    }
                    streams
                        .entry((ev.conn_ptr, ev.direction))
                        .or_default()
                        .extend_from_slice(&ev.payload);
                }
            }
            assert!(saw_positive_fd, "expected SSL_set_fd FD correlation");

            let egress_all: Vec<String> = streams
                .iter()
                .filter(|((_, dir), _)| *dir == 0)
                .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
                .collect();
            let ingress_all: Vec<String> = streams
                .iter()
                .filter(|((_, dir), _)| *dir == 1)
                .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
                .collect();

            for i in 0..1000 {
                let expected_req = format!("REQ|{i:04}|");
                let expected_rsp = format!("RSP|{i:04}|");
                assert!(
                    egress_all.iter().any(|s| s.contains(&expected_req)),
                    "missing plaintext request {expected_req}"
                );
                assert!(
                    ingress_all.iter().any(|s| s.contains(&expected_rsp)),
                    "missing plaintext response {expected_rsp}"
                );
            }
            // Verify full > 16 KB (20,480-byte) contiguous payload recovery across multi-chunk ringbuf
            let found_large = egress_all.iter().any(|s| {
                if let Some(pos) = s.find("REQ|0000|LEN=20480|END|") {
                    s.len() >= pos + 20480 && &s.as_bytes()[pos + 20476..pos + 20480] == b"TAIL"
                } else {
                    false
                }
            });
            assert!(
                found_large,
                "expected contiguous 20,480-byte >16KB plaintext payload recovery ending in TAIL"
            );
        }
        let fds_after = open_fd_count();
        assert_eq!(fds_before, fds_after, "FD leak in OpenSSL TlsInterceptor");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_go_tls13_64_goroutines_ret_uprobes_stack_growth_zero_crashes() {
        let _guard = LIVE_TLS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = temp_work_dir("golang");
        let src = dir.join("main.go");
        let bin = dir.join("go_tls_test");

        let go_code = r#"package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
)

// Force dynamic Go goroutine stack split/move cleanly across frames
//go:noinline
func recurseStack(depth int, conn net.Conn, fn func(net.Conn)) {
	var pad [1024]byte
	pad[0] = byte(depth)
	runtime.KeepAlive(&pad)
	if depth > 0 {
		recurseStack(depth-1, conn, fn)
		return
	}
	fn(conn)
}

func makeSelfSignedCert() tls.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func readExact(c net.Conn, buf []byte) error {
	_, err := io.ReadFull(c, buf)
	return err
}

func writeExact(c net.Conn, buf []byte) error {
	for len(buf) > 0 {
		n, err := c.Write(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}

func handleServerConn(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 32768)
	var hdr [4]byte
	for {
		var err error
		recurseStack(24, c, func(nc net.Conn) {
			err = readExact(nc, hdr[:])
		})
		if err != nil {
			return
		}
		plen := binary.BigEndian.Uint32(hdr[:])
		if plen == 0 || plen > 32768 {
			return
		}
		recurseStack(24, c, func(nc net.Conn) {
			err = readExact(nc, buf[:plen])
		})
		if err != nil {
			return
		}
		buf[0] = 'G'
		buf[1] = 'R'
		buf[2] = 'P'
		buf[3] = 'C'
		recurseStack(20, c, func(nc net.Conn) {
			if e := writeExact(nc, hdr[:]); e != nil {
				err = e
				return
			}
			err = writeExact(nc, buf[:plen])
		})
		if err != nil {
			return
		}
	}
}

func main() {
	cert := makeSelfSignedCert()
	srvCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	cliCfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Printf("READY %s\n", ln.Addr().String())
	os.Stdout.Sync()

	rd := bufio.NewReader(os.Stdin)
	_, _ = rd.ReadString('\n')

	var acceptWg sync.WaitGroup
	acceptWg.Add(1)
	go func() {
		defer acceptWg.Done()
		for i := 0; i < 64; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleServerConn(c)
		}
	}()

	var wg sync.WaitGroup
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			conn, err := tls.Dial("tcp", ln.Addr().String(), cliCfg)
			if err != nil {
				panic(err)
			}
			defer conn.Close()

			for iter := 0; iter < 8; iter++ {
				plen := 128
				if iter == 7 && gid%16 == 0 {
					plen = 20480 // > 16 KB chunk test
				}
				payload := make([]byte, plen)
				for i := range payload {
					payload[i] = byte('A' + ((gid + i) % 26))
				}
				hdrTag := fmt.Sprintf("GOREQ|%02d|%02d|", gid, iter)
				copy(payload, []byte(hdrTag))

				var lh [4]byte
				binary.BigEndian.PutUint32(lh[:], uint32(plen))

				recurseStack(24, conn, func(nc net.Conn) {
					if e := writeExact(nc, lh[:]); e != nil {
						panic(e)
					}
					if e := writeExact(nc, payload); e != nil {
						panic(e)
					}
				})

				var rh [4]byte
				rsp := make([]byte, plen)
				recurseStack(24, conn, func(nc net.Conn) {
					if e := readExact(nc, rh[:]); e != nil {
						panic(e)
					}
					if binary.BigEndian.Uint32(rh[:]) != uint32(plen) {
						panic("length mismatch")
					}
					if e := readExact(nc, rsp); e != nil {
						panic(e)
					}
				})
				runtime.Gosched()
			}
		}(g)
	}
	wg.Wait()
	acceptWg.Wait()
}
"#;
        std::fs::write(&src, go_code).unwrap();
        let build = Command::new("go")
            .args(["build", "-o"])
            .arg(&bin)
            .arg(&src)
            .output()
            .expect("go build");
        assert!(
            build.status.success(),
            "go build failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        // 1. Cross-check pure-Rust ret_scanner against real `objdump -d` RET offsets on Go 1.26!
        let go_bytes = std::fs::read(&bin).unwrap();
        let plan = resolve_go_tls_probes(bin.to_str().unwrap(), &go_bytes).unwrap();
        assert!(!plan.read.ret_file_offsets.is_empty());
        assert!(!plan.write.ret_file_offsets.is_empty());
        let expected_read_rets =
            objdump_ret_offsets(&bin, "crypto/tls.(*Conn).Read", plan.read.entry_file_offset);
        let expected_write_rets = objdump_ret_offsets(
            &bin,
            "crypto/tls.(*Conn).Write",
            plan.write.entry_file_offset,
        );
        assert_eq!(
            plan.read.ret_file_offsets, expected_read_rets,
            "ret_scanner must match objdump RET offsets 100% for crypto/tls.(*Conn).Read"
        );
        assert_eq!(
            plan.write.ret_file_offsets, expected_write_rets,
            "ret_scanner must match objdump RET offsets 100% for crypto/tls.(*Conn).Write"
        );

        // 2. Live 64-goroutine TLS 1.3 interception using ONLY RET-offset entry uprobes
        let fds_before = open_fd_count();
        {
            let oss_bpf = std::fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../probes/build/tls_openssl.bpf.o"),
            )
            .unwrap();
            let go_bpf = std::fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../probes/build/tls_go.bpf.o"),
            )
            .unwrap();

            let interceptor =
                Arc::new(Mutex::new(TlsInterceptor::load(&oss_bpf, &go_bpf).unwrap()));

            let mut child = Command::new(&bin)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("spawn go_tls_test");
            let child_pid = child.id();

            let mut stdout_reader = BufReader::new(child.stdout.take().unwrap());
            let mut ready_line = String::new();
            stdout_reader.read_line(&mut ready_line).unwrap();
            assert!(ready_line.starts_with("READY "), "got {ready_line}");

            let disc = discover_pid_tls_targets(child_pid).unwrap();
            assert!(
                !disc.go_binary_paths.is_empty(),
                "expected Go TLS binary discovered via /proc/<pid>/maps"
            );

            let summary = interceptor.lock().unwrap().attach_pid(child_pid).unwrap();
            assert!(
                summary.go_ret_offsets_attached
                    == plan.read.ret_file_offsets.len() + plan.write.ret_file_offsets.len(),
                "unexpected RET uprobe count: {summary:?}"
            );

            let stop = Arc::new(AtomicBool::new(false));
            let drainer = drain_until_done(Arc::clone(&interceptor), Arc::clone(&stop));

            {
                let mut stdin = child.stdin.take().unwrap();
                writeln!(stdin, "GO").unwrap();
                stdin.flush().unwrap();
            }

            let status = child.wait().expect("wait go_tls_test");
            stop.store(true, Ordering::Release);
            let events = drainer.join().unwrap();
            assert!(
                status.success(),
                "Go binary must complete 64 goroutines x 8 iterations with ZERO crashes! got {status}"
            );
            let drops = interceptor.lock().unwrap().read_ringbuf_drops().unwrap();
            assert_eq!(drops, 0, "expected 0 RingBuf drops in Go probe");

            // Reassemble payloads per (conn_ptr, direction) and verify all 512 messages
            let mut streams: std::collections::HashMap<(u64, u8), Vec<u8>> =
                std::collections::HashMap::new();
            let mut conns_seen = HashSet::new();
            for ev in &events {
                if ev.tls_source == 2 {
                    conns_seen.insert(ev.conn_ptr);
                    streams
                        .entry((ev.conn_ptr, ev.direction))
                        .or_default()
                        .extend_from_slice(&ev.payload);
                }
            }
            assert!(
                conns_seen.len() >= 64,
                "expected >= 64 TLS conn pointers, got {}",
                conns_seen.len()
            );

            let egress_streams: Vec<String> = streams
                .iter()
                .filter(|((_, d), _)| *d == 0)
                .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
                .collect();
            let ingress_streams: Vec<String> = streams
                .iter()
                .filter(|((_, d), _)| *d == 1)
                .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
                .collect();
            for g in 0..64 {
                for iter in 0..8 {
                    let req = format!("GOREQ|{g:02}|{iter:02}|");
                    let rsp = format!("GRPCQ|{g:02}|{iter:02}|");
                    assert!(
                        egress_streams.iter().any(|s| s.contains(&req)),
                        "missing Go TLS egress plaintext {req}"
                    );
                    assert!(
                        ingress_streams.iter().any(|s| s.contains(&rsp)),
                        "missing Go TLS ingress plaintext {rsp}"
                    );
                }
            }
            assert!(
                egress_streams.iter().any(|s| s.len() >= 20480),
                "expected >16 KB multi-chunk Go TLS payload captured on egress"
            );
        }
        let fds_after = open_fd_count();
        assert_eq!(fds_before, fds_after, "FD leak in Go TlsInterceptor");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
