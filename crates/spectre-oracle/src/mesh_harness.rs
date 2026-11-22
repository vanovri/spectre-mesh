use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use spectre_l7::{ConnConfig, Direction, L7Chunk, L7Protocol, L7Reassembler, L7Span};
use spectre_tls::TlsInterceptor;
use spectre_xdp::{
    run_in_isolated_netns, send_raw_l2_frames, NetlinkSocket, RateLimitConfig, TcpMonitor,
    XdpFirewall, XDP_FLAGS_SKB_MODE,
};

use crate::oracle::{evaluate_leg_parity, GroundTruthRecord, OracleReport};
use crate::OracleError;

#[derive(Debug, Clone)]
pub struct MeshOracleConfig {
    pub total_requests: usize,
    pub max_p99_delta_ms: f64,
    pub probe_dir: PathBuf,
}

impl Default for MeshOracleConfig {
    fn default() -> Self {
        Self {
            total_requests: 50_000,
            max_p99_delta_ms: 2.0,
            probe_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../probes/build"),
        }
    }
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().map_or(0, Child::id)
    }

    fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        self.child.as_mut().and_then(|c| c.stdin.take())
    }

    fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.as_mut().and_then(|c| c.stdout.take())
    }

    fn wait_success(mut self) -> Result<std::process::ExitStatus, OracleError> {
        let mut c = self.child.take().unwrap();
        Ok(c.wait()?)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|it| it.count())
        .unwrap_or(0)
}

fn make_temp_dir(tag: &str) -> Result<PathBuf, OracleError> {
    let dir = std::env::temp_dir().join(format!("spectre_m07_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn pick_free_port() -> Result<u16, OracleError> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

struct DrainContext {
    tls: Arc<Mutex<TlsInterceptor>>,
    tcp: Arc<Mutex<TcpMonitor>>,
    reasm: Arc<Mutex<L7Reassembler>>,
    tls_conn_fd: Mutex<HashMap<(u32, u64), i32>>,
    stop: Arc<AtomicBool>,
}

fn spawn_drain_worker(ctx: Arc<DrainContext>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !ctx.stop.load(Ordering::Acquire) {
            drain_once(&ctx);
            std::thread::sleep(Duration::from_micros(400));
        }
        // Final drain barrier after workloads settle
        std::thread::sleep(Duration::from_millis(30));
        drain_once(&ctx);
    })
}

fn drain_once(ctx: &DrainContext) {
    let mut tls_events = {
        let mut t = ctx.tls.lock().unwrap();
        t.drain_tls_events()
    };
    let mut tcp_events = {
        let mut m = ctx.tcp.lock().unwrap();
        m.drain_l7_events()
    };
    if tls_events.is_empty() && tcp_events.is_empty() {
        return;
    }
    tls_events.sort_by_key(|e| (e.ts_ns, e.chunk_seq));
    tcp_events.sort_by_key(|e| (e.ts_ns, e.chunk_seq));

    let mut fd_map = ctx.tls_conn_fd.lock().unwrap();
    let mut reasm = ctx.reasm.lock().unwrap();

    for ev in &tls_events {
        // Keep stable canonical fd per (pid, conn_ptr) even if first SSL call preceded SSL_set_fd
        let canon_fd = *fd_map.entry((ev.pid, ev.conn_ptr)).or_insert(ev.fd);
        reasm.ingest(&L7Chunk {
            conn_id: ev.conn_ptr,
            pid: ev.pid,
            fd: canon_fd,
            ts_ns: ev.ts_ns,
            direction: Direction::from_u8(ev.direction),
            tls_source: ev.tls_source,
            payload: &ev.payload,
        });
    }
    for ev in &tcp_events {
        reasm.ingest(&L7Chunk {
            conn_id: 0,
            pid: ev.pid,
            fd: ev.fd,
            ts_ns: ev.ts_ns,
            direction: Direction::from_u8(ev.direction),
            tls_source: ev.tls_source,
            payload: &ev.payload,
        });
    }
}

fn parse_truth_tsv(raw: &str, proto: L7Protocol) -> Result<Vec<GroundTruthRecord>, OracleError> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let mut cols = t.split('\t');
        let Some(method) = cols.next() else {
            continue;
        };
        let Some(target) = cols.next() else {
            continue;
        };
        let Some(status_s) = cols.next() else {
            continue;
        };
        let Some(lat_s) = cols.next() else {
            continue;
        };
        let status_code = status_s
            .parse::<u16>()
            .map_err(|e| OracleError::VerificationFailed(format!("bad truth status: {e}")))?;
        let latency_ns = lat_s
            .parse::<u64>()
            .map_err(|e| OracleError::VerificationFailed(format!("bad truth latency: {e}")))?;
        out.push(GroundTruthRecord {
            protocol: proto,
            method: method.to_owned(),
            expected_target: target.to_owned(),
            status_code,
            latency_ns,
        });
    }
    Ok(out)
}

fn build_openssl_mesh_node(dir: &Path) -> Result<PathBuf, OracleError> {
    let src = dir.join("openssl_mesh_node.c");
    let bin = dir.join("openssl_mesh_node");
    let code = r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void write_exact_ssl(SSL *ssl, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int w = SSL_write(ssl, buf + off, (int)(len - off));
        if (w <= 0) exit(21);
        off += (size_t)w;
    }
}

static int read_some_ssl(SSL *ssl, uint8_t *buf, size_t cap) {
    int r = SSL_read(ssl, buf, (int)cap);
    return r;
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
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"localhost", -1, -1, 0);
    X509_set_issuer_name(x, name);
    X509_sign(x, pkey, EVP_sha256());

    *out_key = pkey;
    *out_cert = x;
}

typedef struct {
    SSL_CTX *ctx;
    int cfd;
} srv_conn_t;

static void *srv_worker(void *arg) {
    srv_conn_t *sc = (srv_conn_t *)arg;
    int nodelay = 1;
    setsockopt(sc->cfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    SSL *ssl = SSL_new(sc->ctx);
    SSL_set_fd(ssl, sc->cfd);
    if (SSL_accept(ssl) != 1) {
        SSL_free(ssl);
        close(sc->cfd);
        free(sc);
        return NULL;
    }
    uint8_t *buf = malloc(65536);
    size_t used = 0;
    for (;;) {
        char *hdr_end = NULL;
        size_t cl = 0;
        for (;;) {
            if (used >= 4) {
                buf[used] = 0;
                hdr_end = strstr((char *)buf, "\r\n\r\n");
                if (hdr_end) {
                    char *cl_ptr = strstr((char *)buf, "Content-Length: ");
                    if (cl_ptr && cl_ptr < hdr_end) {
                        cl = (size_t)atoi(cl_ptr + 16);
                    }
                    size_t hdr_len = (size_t)(hdr_end - (char *)buf) + 4;
                    if (used >= hdr_len + cl) {
                        size_t consumed = hdr_len + cl;
                        const char *resp = NULL;
                        if (strstr((char *)buf, "/api/v1/fault") && strstr((char *)buf, "/api/v1/fault") < hdr_end) {
                            resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nbusy";
                        } else if (strncmp((char *)buf, "POST ", 5) == 0) {
                            resp = "HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok";
                        } else {
                            resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                        }
                        write_exact_ssl(ssl, (const uint8_t *)resp, strlen(resp));
                        size_t rem = used - consumed;
                        if (rem > 0) memmove(buf, buf + consumed, rem);
                        used = rem;
                        break;
                    }
                }
            }
            int r = read_some_ssl(ssl, buf + used, 65535 - used);
            if (r <= 0) {
                free(buf);
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(sc->cfd);
                free(sc);
                return NULL;
            }
            used += (size_t)r;
        }
    }
}

static int run_server(uint16_t port) {
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    gen_cert(&pkey, &cert);

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_use_certificate(ctx, cert);
    SSL_CTX_use_PrivateKey(ctx, pkey);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) exit(11);
    if (listen(lfd, 64) != 0) exit(12);

    printf("LISTEN\n");
    fflush(stdout);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) continue;
        srv_conn_t *sc = malloc(sizeof(srv_conn_t));
        sc->ctx = ctx;
        sc->cfd = cfd;
        pthread_t th;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&th, &attr, srv_worker, sc);
        pthread_attr_destroy(&attr);
    }
    return 0;
}

typedef struct {
    SSL_CTX *ctx;
    uint16_t port;
    int worker_id;
    int start_idx;
    int count;
    char *truth_buf;
    size_t truth_cap;
    size_t truth_len;
} cli_args_t;

static void *cli_worker(void *arg) {
    cli_args_t *ca = (cli_args_t *)arg;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int nodelay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ca->port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) exit(31);

    SSL *ssl = SSL_new(ca->ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) exit(32);

    char req[512];
    uint8_t rbuf[4096];
    for (int i = 0; i < ca->count; i++) {
        int gidx = ca->start_idx + i;
        const char *method = "GET";
        char path[96];
        const char *body = "";
        int blen = 0;
        int exp_status = 200;

        if (gidx % 250 == 49) {
            snprintf(path, sizeof(path), "/api/v1/fault?i=%d", gidx);
            exp_status = 503;
        } else if (gidx % 5 == 0) {
            method = "POST";
            snprintf(path, sizeof(path), "/api/v1/orders?i=%d", gidx);
            body = "{\"item\":\"mesh\"}";
            blen = 15;
            exp_status = 201;
        } else {
            snprintf(path, sizeof(path), "/api/v1/items?i=%d", gidx);
        }

        int n = snprintf(
            req, sizeof(req),
            "%s %s HTTP/1.1\r\nHost: mesh.local\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-%016x-01\r\nContent-Length: %d\r\n\r\n%s",
            method, path, gidx + 1, blen, body
        );

        uint64_t t0 = now_ns();
        write_exact_ssl(ssl, (const uint8_t *)req, (size_t)n);

        size_t rused = 0;
        for (;;) {
            int r = read_some_ssl(ssl, rbuf + rused, sizeof(rbuf) - 1 - rused);
            if (r <= 0) exit(33);
            rused += (size_t)r;
            rbuf[rused] = 0;
            char *hend = strstr((char *)rbuf, "\r\n\r\n");
            if (hend) {
                char *clp = strstr((char *)rbuf, "Content-Length: ");
                size_t rcl = clp ? (size_t)atoi(clp + 16) : 0;
                size_t hlen = (size_t)(hend - (char *)rbuf) + 4;
                if (rused >= hlen + rcl) break;
            }
        }
        uint64_t dt = now_ns() - t0;

        if (ca->truth_len + 128 < ca->truth_cap) {
            ca->truth_len += (size_t)snprintf(
                ca->truth_buf + ca->truth_len,
                ca->truth_cap - ca->truth_len,
                "%s\t%s\t%d\t%llu\n",
                method, path, exp_status, (unsigned long long)dt
            );
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    return NULL;
}

static int run_client(uint16_t port, int workers, int total, const char *out_path) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    printf("READY\n");
    fflush(stdout);

    char cmd[32];
    if (!fgets(cmd, sizeof(cmd), stdin)) return 41;

    pthread_t *ths = calloc((size_t)workers, sizeof(pthread_t));
    cli_args_t *args = calloc((size_t)workers, sizeof(cli_args_t));
    int base = total / workers;
    int rem = total % workers;
    int off = 0;
    for (int w = 0; w < workers; w++) {
        int c = base + (w < rem ? 1 : 0);
        args[w].ctx = ctx;
        args[w].port = port;
        args[w].worker_id = w;
        args[w].start_idx = off;
        args[w].count = c;
        args[w].truth_cap = (size_t)(c + 1) * 128;
        args[w].truth_buf = malloc(args[w].truth_cap);
        args[w].truth_len = 0;
        off += c;
        pthread_create(&ths[w], NULL, cli_worker, &args[w]);
    }
    for (int w = 0; w < workers; w++) {
        pthread_join(ths[w], NULL);
    }

    FILE *fp = fopen(out_path, "wb");
    if (!fp) return 42;
    for (int w = 0; w < workers; w++) {
        fwrite(args[w].truth_buf, 1, args[w].truth_len, fp);
        free(args[w].truth_buf);
    }
    fclose(fp);
    free(ths);
    free(args);
    SSL_CTX_free(ctx);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "server") == 0) {
        return run_server((uint16_t)atoi(argv[2]));
    }
    if (argc >= 6 && strcmp(argv[1], "client") == 0) {
        return run_client((uint16_t)atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), argv[5]);
    }
    return 1;
}
"#;
    std::fs::write(&src, code)?;
    let out = Command::new("gcc")
        .args([
            "-O2",
            "-Wall",
            "-Wextra",
            src.to_str().unwrap(),
            "-o",
            bin.to_str().unwrap(),
            "-lssl",
            "-lcrypto",
            "-lpthread",
        ])
        .output()?;
    if !out.status.success() {
        return Err(OracleError::BuildFailed(format!(
            "gcc openssl_mesh_node failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(bin)
}

fn build_go_mesh_node(dir: &Path) -> Result<PathBuf, OracleError> {
    let go_dir = dir.join("go_node");
    std::fs::create_dir_all(&go_dir)?;
    std::fs::write(go_dir.join("go.mod"), "module spectre_m07_go\ngo 1.22\n")?;
    let bin = dir.join("go_mesh_node");
    let go_src = r#"package main

import (
	"bufio"
	"bytes"
	"context"
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
	"net/http"
	"net/http/httptrace"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:noinline
func recurseStack(depth int, fn func()) {
	var pad [1024]byte
	pad[0] = byte(depth)
	runtime.KeepAlive(&pad)
	if depth > 0 {
		recurseStack(depth-1, fn)
		return
	}
	fn()
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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func runServer(addr string) {
	cert := makeSelfSignedCert()
	mux := http.NewServeMux()
	mux.HandleFunc("/spectre.MeshService/Infer", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Add("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		var frame [11]byte
		// 5-byte gRPC prefix (uncompressed, len=6) + protobuf tag 1 string "ok" (4B) + tag 2 varint 7 (2B)
		frame[0] = 0
		binary.BigEndian.PutUint32(frame[1:5], 6)
		frame[5] = 0x0a
		frame[6] = 0x02
		frame[7] = 'o'
		frame[8] = 'k'
		frame[9] = 0x10
		frame[10] = 7
		_, _ = w.Write(frame[:])
		w.Header().Set("Grpc-Status", "0")
	})

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		panic(err)
	}
	fmt.Println("LISTEN")
	srv := &http.Server{Handler: mux, TLSConfig: tlsCfg}
	_ = srv.Serve(ln)
}

func runClient(addr string, workers, total int, outPath string) {
	fmt.Println("READY")
	br := bufio.NewReader(os.Stdin)
	if _, err := br.ReadString('\n'); err != nil {
		os.Exit(41)
	}

	results := make([]string, workers)
	var wg sync.WaitGroup
	base := total / workers
	rem := total % workers
	startIdx := 0

	for w := 0; w < workers; w++ {
		c := base
		if w < rem {
			c++
		}
		myStart := startIdx
		startIdx += c
		wid := w
		wg.Add(1)
		go func(wIdx, off, count int) {
			defer wg.Done()
			tr := &http.Transport{
				ForceAttemptHTTP2: true,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS13,
					MaxVersion:         tls.VersionTLS13,
					NextProtos:         []string{"h2"},
				},
			}
			defer tr.CloseIdleConnections()
			cli := &http.Client{Transport: tr}

			var sb strings.Builder
			sb.Grow(count * 64)
			url := "https://" + addr + "/spectre.MeshService/Infer"

			var payload [11]byte
			payload[0] = 0
			binary.BigEndian.PutUint32(payload[1:5], 6)
			payload[5] = 0x0a
			payload[6] = 0x02
			payload[7] = 'g'
			payload[8] = 'o'
			payload[9] = 0x10
			payload[10] = 1

			for i := 0; i < count; i++ {
				gidx := off + i
				doCall := func() {
					t0 := time.Now()
					trace := &httptrace.ClientTrace{
						GotConn: func(_ httptrace.GotConnInfo) {
							t0 = time.Now()
						},
					}
					ctx := httptrace.WithClientTrace(context.Background(), trace)
					req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload[:]))
					req.Header.Set("Content-Type", "application/grpc")
					req.Header.Set("traceparent", fmt.Sprintf("00-4bf92f3577b34da6a3ce929d0e0e4736-%016x-01", gidx+1))
					resp, err := cli.Do(req)
					if err != nil {
						panic(err)
					}
					_, _ = io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					dt := time.Since(t0).Nanoseconds()
					sb.WriteString(fmt.Sprintf("POST\t/spectre.MeshService/Infer\t%d\t%d\n", resp.StatusCode, dt))
				}
				if i%128 == 0 {
					// Actively trigger goroutine stack split/move under RET-offset uprobe instrumentation
					recurseStack(24, doCall)
				} else {
					doCall()
				}
			}
			results[wIdx] = sb.String()
		}(wid, myStart, c)
	}
	wg.Wait()

	f, err := os.Create(outPath)
	if err != nil {
		panic(err)
	}
	for _, s := range results {
		_, _ = f.WriteString(s)
	}
	_ = f.Close()
}

func main() {
	if len(os.Args) >= 3 && os.Args[1] == "server" {
		runServer(os.Args[2])
		return
	}
	if len(os.Args) >= 6 && os.Args[1] == "client" {
		w, _ := strconv.Atoi(os.Args[3])
		n, _ := strconv.Atoi(os.Args[4])
		runClient(os.Args[2], w, n, os.Args[5])
		return
	}
	os.Exit(1)
}
"#;
    std::fs::write(go_dir.join("main.go"), go_src)?;
    let out = Command::new("go")
        .current_dir(&go_dir)
        .args(["build", "-o", bin.to_str().unwrap(), "."])
        .output()?;
    if !out.status.success() {
        return Err(OracleError::BuildFailed(format!(
            "go build go_mesh_node failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(bin)
}

fn build_rust_l7_client(dir: &Path) -> Result<PathBuf, OracleError> {
    let src = dir.join("rust_l7_client.rs");
    let bin = dir.join("rust_l7_client");
    let code = r#"
use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::time::Instant;

fn read_pg_until_ready(stream: &mut TcpStream) {
    let mut hdr = [0u8; 5];
    let mut body = Vec::new();
    loop {
        stream.read_exact(&mut hdr).unwrap();
        let tag = hdr[0];
        let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        let blen = len.saturating_sub(4);
        body.resize(blen, 0);
        if blen > 0 {
            stream.read_exact(&mut body).unwrap();
        }
        if tag == b'Z' {
            break;
        }
    }
}

fn read_resp_line(stream: &mut TcpStream, buf: &mut Vec<u8>) {
    buf.clear();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).unwrap();
        buf.push(byte[0]);
        if buf.len() >= 2 && buf[buf.len() - 2] == b'\r' && buf[buf.len() - 1] == b'\n' {
            break;
        }
    }
}

fn read_one_redis_reply(stream: &mut TcpStream) {
    let mut line = Vec::with_capacity(64);
    read_resp_line(stream, &mut line);
    if line.first() == Some(&b'$') {
        let len_s = std::str::from_utf8(&line[1..line.len() - 2]).unwrap();
        let blen: isize = len_s.parse().unwrap();
        if blen >= 0 {
            let mut bulk = vec![0u8; (blen as usize) + 2];
            stream.read_exact(&mut bulk).unwrap();
        }
    }
}

fn make_pg_startup() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&196_608u32.to_be_bytes());
    body.extend_from_slice(b"user\0spectre\0database\0mesh\0\0");
    let total = (4 + body.len()) as u32;
    let mut pkt = Vec::with_capacity(total as usize);
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt
}

fn make_pg_query(sql: &str) -> Vec<u8> {
    let total = (4 + sql.len() + 1) as u32;
    let mut pkt = Vec::with_capacity(1 + total as usize);
    pkt.push(b'Q');
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(sql.as_bytes());
    pkt.push(0);
    pkt
}

fn run_pg(addr: String, conns: usize, total: usize) {
    let mut streams = Vec::with_capacity(conns);
    for _ in 0..conns {
        let s = TcpStream::connect(&addr).unwrap();
        s.set_nodelay(true).unwrap();
        streams.push(s);
    }

    println!("READY");
    let _ = std::io::stdout().flush();
    let mut go = String::new();
    let _ = std::io::stdin().lock().read_line(&mut go);

    // Send PG Startup handshake per connection
    let startup = make_pg_startup();
    for s in &mut streams {
        s.write_all(&startup).unwrap();
        read_pg_until_ready(s);
    }

    let mut handles = Vec::new();
    let base = total / conns;
    let rem = total % conns;
    let mut off = 0usize;
    for (wid, stream) in streams.into_iter().enumerate() {
        let count = base + usize::from(wid < rem);
        let start_idx = off;
        off += count;
        handles.push(std::thread::spawn(move || {
            let mut s = stream;
            let mut recs = String::with_capacity(count * 64);
            for i in 0..count {
                let gidx = start_idx + i;
                let (method, sql, expected_fp) = if gidx % 250 == 99 {
                    (
                        "SELECT",
                        format!("SELECT payload FROM slow_audit WHERE id = {gidx}"),
                        "SELECT payload FROM slow_audit WHERE id = $1",
                    )
                } else if gidx % 4 == 0 {
                    (
                        "INSERT",
                        format!("INSERT INTO events (id, msg) VALUES ({gidx}, 'ok_{gidx}')"),
                        "INSERT INTO events (id, msg) VALUES ($1, $2)",
                    )
                } else {
                    (
                        "SELECT",
                        format!("SELECT id FROM orders WHERE id = {gidx} AND name = 'item_{gidx}'"),
                        "SELECT id FROM orders WHERE id = $1 AND name = $2",
                    )
                };
                let pkt = make_pg_query(&sql);
                let t0 = Instant::now();
                s.write_all(&pkt).unwrap();
                read_pg_until_ready(&mut s);
                let dt = t0.elapsed().as_nanos() as u64;
                use std::fmt::Write;
                let _ = writeln!(recs, "{method}\t{expected_fp}\t200\t{dt}");
            }
            recs
        }));
    }

    // Write truth lines over stdout (fd = 1, excluded from tcp_trace.bpf.c fd < 3 check)
    let mut stdout = std::io::stdout().lock();
    for h in handles {
        let block = h.join().unwrap();
        stdout.write_all(block.as_bytes()).unwrap();
    }
    stdout.flush().unwrap();
}

fn run_redis(addr: String, conns: usize, total: usize) {
    let mut streams = Vec::with_capacity(conns);
    for _ in 0..conns {
        let s = TcpStream::connect(&addr).unwrap();
        s.set_nodelay(true).unwrap();
        streams.push(s);
    }

    println!("READY");
    let _ = std::io::stdout().flush();
    let mut go = String::new();
    let _ = std::io::stdin().lock().read_line(&mut go);

    let mut handles = Vec::new();
    let base = total / conns;
    let rem = total % conns;
    let mut off = 0usize;
    for (wid, stream) in streams.into_iter().enumerate() {
        let count = base + usize::from(wid < rem);
        let start_idx = off;
        off += count;
        handles.push(std::thread::spawn(move || {
            let mut s = stream;
            let mut recs = String::with_capacity(count * 48);
            for i in 0..count {
                let gidx = start_idx + i;
                let (method, prefix, cmd) = if gidx % 2 == 0 {
                    let key = format!("user:{gidx}");
                    let val = format!("tok_{gidx}");
                    (
                        "SET",
                        "user:",
                        format!(
                            "*3\r\n$3\r\nSET\r\n${}\r\n{}\r\n${}\r\n{}\r\n",
                            key.len(),
                            key,
                            val.len(),
                            val
                        ),
                    )
                } else {
                    let key = format!("order:{gidx}");
                    (
                        "GET",
                        "order:",
                        format!("*2\r\n$3\r\nGET\r\n${}\r\n{}\r\n", key.len(), key),
                    )
                };
                let t0 = Instant::now();
                s.write_all(cmd.as_bytes()).unwrap();
                read_one_redis_reply(&mut s);
                let dt = t0.elapsed().as_nanos() as u64;
                use std::fmt::Write;
                let _ = writeln!(recs, "{method}\t{prefix}\t200\t{dt}");
            }
            recs
        }));
    }

    let mut stdout = std::io::stdout().lock();
    for h in handles {
        let block = h.join().unwrap();
        stdout.write_all(block.as_bytes()).unwrap();
    }
    stdout.flush().unwrap();
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap();
    let addr = args.next().unwrap();
    let conns: usize = args.next().unwrap().parse().unwrap();
    let total: usize = args.next().unwrap().parse().unwrap();
    match mode.as_str() {
        "pg" => run_pg(addr, conns, total),
        "redis" => run_redis(addr, conns, total),
        _ => std::process::exit(2),
    }
}
"#;
    std::fs::write(&src, code)?;
    let out = Command::new("rustc")
        .args(["-O", src.to_str().unwrap(), "-o", bin.to_str().unwrap()])
        .output()?;
    if !out.status.success() {
        return Err(OracleError::BuildFailed(format!(
            "rustc rust_l7_client failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(bin)
}

fn spawn_pg_server(
    stop: Arc<AtomicBool>,
) -> Result<(u16, std::thread::JoinHandle<()>), OracleError> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let handle = std::thread::spawn(move || {
        let mut workers = Vec::new();
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    workers.push(std::thread::spawn(move || serve_pg_conn(stream)));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        for w in workers {
            let _ = w.join();
        }
    });
    Ok((port, handle))
}

fn serve_pg_conn(mut stream: TcpStream) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_nodelay(true);

    let mut hdr4 = [0u8; 4];
    if stream.read_exact(&mut hdr4).is_err() {
        return;
    }
    let startup_len = u32::from_be_bytes(hdr4) as usize;
    if !(8..=16_384).contains(&startup_len) {
        return;
    }
    let mut sbuf = vec![0u8; startup_len - 4];
    if stream.read_exact(&mut sbuf).is_err() {
        return;
    }
    // AuthenticationOk ('R', len=8, 0) + ReadyForQuery ('Z', len=5, 'I')
    let mut hello = Vec::with_capacity(15);
    hello.push(b'R');
    hello.extend_from_slice(&8u32.to_be_bytes());
    hello.extend_from_slice(&0u32.to_be_bytes());
    hello.push(b'Z');
    hello.extend_from_slice(&5u32.to_be_bytes());
    hello.push(b'I');
    if stream.write_all(&hello).is_err() {
        return;
    }

    let mut qhdr = [0u8; 5];
    let mut qbody = Vec::new();
    while stream.read_exact(&mut qhdr).is_ok() {
        let tag = qhdr[0];
        let qlen = u32::from_be_bytes([qhdr[1], qhdr[2], qhdr[3], qhdr[4]]) as usize;
        if !(4..=1_048_576).contains(&qlen) {
            break;
        }
        qbody.resize(qlen - 4, 0);
        if qlen > 4 && stream.read_exact(&mut qbody).is_err() {
            break;
        }
        if tag == b'X' {
            break;
        }
        let query = String::from_utf8_lossy(&qbody);
        if query.contains("slow_audit") {
            std::thread::sleep(Duration::from_millis(4));
        }

        // DataRow ('D', 1 col = "ok") + CommandComplete ('C', "SELECT 1\0") + ReadyForQuery ('Z', 'I')
        let mut resp = Vec::with_capacity(64);
        resp.push(b'D');
        resp.extend_from_slice(&12u32.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&2u32.to_be_bytes());
        resp.extend_from_slice(b"ok");

        let complete = b"SELECT 1\0";
        resp.push(b'C');
        resp.extend_from_slice(&((4 + complete.len()) as u32).to_be_bytes());
        resp.extend_from_slice(complete);

        resp.push(b'Z');
        resp.extend_from_slice(&5u32.to_be_bytes());
        resp.push(b'I');

        if stream.write_all(&resp).is_err() {
            break;
        }
    }
}

fn spawn_redis_server(
    stop: Arc<AtomicBool>,
) -> Result<(u16, std::thread::JoinHandle<()>), OracleError> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let handle = std::thread::spawn(move || {
        let mut workers = Vec::new();
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    workers.push(std::thread::spawn(move || serve_redis_conn(stream)));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        for w in workers {
            let _ = w.join();
        }
    });
    Ok((port, handle))
}

fn serve_redis_conn(mut stream: TcpStream) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_nodelay(true);
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        // Check if at least one full RESP array `*N\r\n($len\r\n<bytes>\r\n){N}` is buffered
        while let Some((consumed, is_set)) = try_consume_resp_cmd(&buf) {
            let reply: &[u8] = if is_set {
                b"+OK\r\n"
            } else {
                b"$5\r\nvalue\r\n"
            };
            if stream.write_all(reply).is_err() {
                return;
            }
            buf.drain(..consumed);
        }
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
}

fn try_consume_resp_cmd(buf: &[u8]) -> Option<(usize, bool)> {
    if !buf.starts_with(b"*") {
        return None;
    }
    let crlf1 = buf.windows(2).position(|w| w == b"\r\n")?;
    let count: usize = std::str::from_utf8(&buf[1..crlf1]).ok()?.parse().ok()?;
    let mut cur = crlf1 + 2;
    let mut is_set = false;
    for idx in 0..count {
        if *buf.get(cur)? != b'$' {
            return None;
        }
        let rel_crlf = buf[cur..].windows(2).position(|w| w == b"\r\n")?;
        let blen: usize = std::str::from_utf8(&buf[cur + 1..cur + rel_crlf])
            .ok()?
            .parse()
            .ok()?;
        let data_start = cur + rel_crlf + 2;
        let data_end = data_start + blen;
        if buf.len() < data_end + 2 {
            return None;
        }
        if idx == 0 {
            is_set = buf[data_start..data_end].eq_ignore_ascii_case(b"SET");
        }
        cur = data_end + 2;
    }
    Some((cur, is_set))
}

fn run_xdp_flood_check(xdp_bpf: &[u8], scratch_dir: &Path) -> Result<u64, OracleError> {
    let xdp_bytes = xdp_bpf.to_vec();
    let count_path = scratch_dir.join("xdp_drops.txt");
    let child_path = count_path.clone();

    run_in_isolated_netns(move || {
        let mut nl = NetlinkSocket::open().map_err(|e| e.to_string())?;
        nl.create_veth_pair("sp_m07_0", "sp_m07_1")
            .map_err(|e| e.to_string())?;
        let idx0 = NetlinkSocket::get_ifindex("sp_m07_0").map_err(|e| e.to_string())?;
        let idx1 = NetlinkSocket::get_ifindex("sp_m07_1").map_err(|e| e.to_string())?;
        nl.add_ipv4_addr(idx0, [10, 200, 0, 1], 24)
            .map_err(|e| e.to_string())?;
        nl.add_ipv4_addr(idx1, [10, 200, 0, 2], 24)
            .map_err(|e| e.to_string())?;
        nl.set_link_up(idx0).map_err(|e| e.to_string())?;
        nl.set_link_up(idx1).map_err(|e| e.to_string())?;
        std::thread::sleep(Duration::from_millis(15));

        let mut fw = XdpFirewall::load_from_bytes(&xdp_bytes).map_err(|e| e.to_string())?;
        fw.set_rate_limit(RateLimitConfig {
            rate_tokens_per_sec: 1,
            burst_tokens: 5,
            enabled: true,
            syn_only: true,
        })
        .map_err(|e| e.to_string())?;
        fw.attach_interface(idx1, XDP_FLAGS_SKB_MODE)
            .map_err(|e| e.to_string())?;

        let frame = make_syn_l2_frame();
        let frames: Vec<&[u8]> = vec![&frame[..]; 200];
        send_raw_l2_frames(idx0, &frames).map_err(|e| e.to_string())?;
        std::thread::sleep(Duration::from_millis(80));

        let stats = fw.read_stats().map_err(|e| e.to_string())?;
        if stats.drop_ratelimit == 0 {
            return Err(format!(
                "expected drop_ratelimit > 0 on sp_m07_1, stats={stats:?}"
            ));
        }
        std::fs::write(&child_path, stats.drop_ratelimit.to_string()).map_err(|e| e.to_string())?;
        drop(fw);
        nl.delete_link(idx0).map_err(|e| e.to_string())?;
        Ok(())
    })?;

    let raw = std::fs::read_to_string(&count_path)?;
    raw.trim()
        .parse::<u64>()
        .map_err(|e| OracleError::VerificationFailed(format!("parse xdp_drops: {e}")))
}

fn make_syn_l2_frame() -> [u8; 54] {
    let mut pkt = [0u8; 54];
    pkt[0..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    pkt[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    pkt[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4
    pkt[14] = 0x45; // v4, ihl=5
    pkt[16..18].copy_from_slice(&40u16.to_be_bytes());
    pkt[22] = 64; // TTL
    pkt[23] = 6; // TCP
    pkt[26..30].copy_from_slice(&[10, 200, 0, 1]);
    pkt[30..34].copy_from_slice(&[10, 200, 0, 2]);
    // IP checksum
    let mut sum = 0u32;
    for chunk in pkt[14..34].as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    pkt[24..26].copy_from_slice(&csum.to_be_bytes());
    pkt[34..36].copy_from_slice(&44321u16.to_be_bytes());
    pkt[36..38].copy_from_slice(&8080u16.to_be_bytes());
    pkt[46] = 0x50; // data offset = 5
    pkt[47] = 0x02; // SYN
    pkt[48..50].copy_from_slice(&64240u16.to_be_bytes());
    pkt
}

/// Execute the full live multi-service encrypted mesh oracle across `total_requests`.
pub fn run_live_mesh_oracle(cfg: &MeshOracleConfig) -> Result<OracleReport, OracleError> {
    let fds_before = open_fd_count();
    let overall_start = Instant::now();

    let oss_bpf = std::fs::read(cfg.probe_dir.join("tls_openssl.bpf.o"))?;
    let go_bpf = std::fs::read(cfg.probe_dir.join("tls_go.bpf.o"))?;
    let tcp_bpf = std::fs::read(cfg.probe_dir.join("tcp_trace.bpf.o"))?;
    let xdp_bpf = std::fs::read(cfg.probe_dir.join("xdp_net.bpf.o"))?;

    let dir = make_temp_dir("oracle")?;
    let oss_bin = build_openssl_mesh_node(&dir)?;
    let go_bin = build_go_mesh_node(&dir)?;
    let rust_cli_bin = build_rust_l7_client(&dir)?;

    let tls = Arc::new(Mutex::new(TlsInterceptor::load(&oss_bpf, &go_bpf)?));
    let tcp = Arc::new(Mutex::new(TcpMonitor::load_and_attach(&tcp_bpf, true)?));
    let reasm = Arc::new(Mutex::new(L7Reassembler::new(ConnConfig::default())));

    let stop_drain = Arc::new(AtomicBool::new(false));
    let drain_ctx = Arc::new(DrainContext {
        tls: Arc::clone(&tls),
        tcp: Arc::clone(&tcp),
        reasm: Arc::clone(&reasm),
        tls_conn_fd: Mutex::new(HashMap::new()),
        stop: Arc::clone(&stop_drain),
    });
    let drainer = spawn_drain_worker(Arc::clone(&drain_ctx));

    let per_leg = cfg.total_requests / 4;
    let extra = cfg.total_requests % 4;
    let n_oss = per_leg + usize::from(extra > 0);
    let n_go = per_leg + usize::from(extra > 1);
    let n_pg = per_leg + usize::from(extra > 2);
    let n_redis = per_leg;

    // 1. OpenSSL TLS 1.3 HTTP/1.1 leg
    let oss_truth_path = dir.join("oss_truth.tsv");
    let oss_port = pick_free_port()?;
    let mut oss_srv = ChildGuard::new(
        Command::new(&oss_bin)
            .args(["server", &oss_port.to_string()])
            .stdout(Stdio::piped())
            .spawn()?,
    );
    {
        let mut rdr = BufReader::new(oss_srv.take_stdout().unwrap());
        let mut line = String::new();
        rdr.read_line(&mut line)?;
        if line.trim() != "LISTEN" {
            return Err(OracleError::VerificationFailed(format!(
                "openssl server failed listen: {line:?}"
            )));
        }
    }
    let mut oss_cli = ChildGuard::new(
        Command::new(&oss_bin)
            .args([
                "client",
                &oss_port.to_string(),
                "8",
                &n_oss.to_string(),
                oss_truth_path.to_str().unwrap(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let oss_pid = oss_cli.pid();
    {
        let mut rdr = BufReader::new(oss_cli.take_stdout().unwrap());
        let mut line = String::new();
        rdr.read_line(&mut line)?;
        if line.trim() != "READY" {
            return Err(OracleError::VerificationFailed(format!(
                "openssl client failed ready: {line:?}"
            )));
        }
    }
    tls.lock().unwrap().attach_pid(oss_pid)?;
    {
        let mut stdin = oss_cli.take_stdin().unwrap();
        writeln!(stdin, "GO")?;
        stdin.flush()?;
    }
    let oss_st = oss_cli.wait_success()?;
    drop(oss_srv);
    if !oss_st.success() {
        return Err(OracleError::VerificationFailed(format!(
            "openssl client exited {oss_st}"
        )));
    }
    let oss_truth = parse_truth_tsv(
        &std::fs::read_to_string(&oss_truth_path)?,
        L7Protocol::Http1,
    )?;

    // 2. Go 1.26 crypto/tls TLS 1.3 HTTP/2 + gRPC leg (RET-offset entry uprobes ONLY)
    let go_truth_path = dir.join("go_truth.tsv");
    let go_port = pick_free_port()?;
    let go_addr = format!("127.0.0.1:{go_port}");
    let mut go_srv = ChildGuard::new(
        Command::new(&go_bin)
            .args(["server", &go_addr])
            .stdout(Stdio::piped())
            .spawn()?,
    );
    {
        let mut rdr = BufReader::new(go_srv.take_stdout().unwrap());
        let mut line = String::new();
        rdr.read_line(&mut line)?;
        if line.trim() != "LISTEN" {
            return Err(OracleError::VerificationFailed(format!(
                "go server failed listen: {line:?}"
            )));
        }
    }
    let mut go_cli = ChildGuard::new(
        Command::new(&go_bin)
            .args([
                "client",
                &go_addr,
                "8",
                &n_go.to_string(),
                go_truth_path.to_str().unwrap(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let go_pid = go_cli.pid();
    {
        let mut rdr = BufReader::new(go_cli.take_stdout().unwrap());
        let mut line = String::new();
        rdr.read_line(&mut line)?;
        if line.trim() != "READY" {
            return Err(OracleError::VerificationFailed(format!(
                "go client failed ready: {line:?}"
            )));
        }
    }
    tls.lock().unwrap().attach_pid(go_pid)?;
    {
        let mut stdin = go_cli.take_stdin().unwrap();
        writeln!(stdin, "GO")?;
        stdin.flush()?;
    }
    let go_st = go_cli.wait_success()?;
    drop(go_srv);
    let go_stack_crashes = u64::from(!go_st.success());
    if !go_st.success() {
        return Err(OracleError::VerificationFailed(format!(
            "Go TLS 1.3 HTTP/2+gRPC client crashed or failed under RET-offset uprobes: {go_st}"
        )));
    }
    let go_truth = parse_truth_tsv(&std::fs::read_to_string(&go_truth_path)?, L7Protocol::Grpc)?;

    // 3. PostgreSQL v3 cleartext wire protocol leg
    let stop_pg_srv = Arc::new(AtomicBool::new(false));
    let (pg_port, pg_srv_handle) = spawn_pg_server(Arc::clone(&stop_pg_srv))?;
    let mut pg_cli = ChildGuard::new(
        Command::new(&rust_cli_bin)
            .args([
                "pg",
                &format!("127.0.0.1:{pg_port}"),
                "8",
                &n_pg.to_string(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let pg_pid = pg_cli.pid();
    let mut pg_stdout_rdr = BufReader::new(pg_cli.take_stdout().unwrap());
    {
        let mut line = String::new();
        pg_stdout_rdr.read_line(&mut line)?;
        if line.trim() != "READY" {
            return Err(OracleError::VerificationFailed(format!(
                "pg client failed ready: {line:?}"
            )));
        }
    }
    tcp.lock().unwrap().track_pid(pg_pid)?;
    {
        let mut stdin = pg_cli.take_stdin().unwrap();
        writeln!(stdin, "GO")?;
        stdin.flush()?;
    }
    let mut pg_truth_raw = String::new();
    pg_stdout_rdr.read_to_string(&mut pg_truth_raw)?;
    drop(pg_stdout_rdr);
    let pg_st = pg_cli.wait_success()?;
    stop_pg_srv.store(true, Ordering::Release);
    let _ = pg_srv_handle.join();
    if !pg_st.success() {
        return Err(OracleError::VerificationFailed(format!(
            "PG v3 client exited {pg_st}"
        )));
    }
    let pg_truth = parse_truth_tsv(&pg_truth_raw, L7Protocol::Postgres)?;

    // 4. Redis RESP2/3 cleartext wire protocol leg
    let stop_rd_srv = Arc::new(AtomicBool::new(false));
    let (rd_port, rd_srv_handle) = spawn_redis_server(Arc::clone(&stop_rd_srv))?;
    let mut rd_cli = ChildGuard::new(
        Command::new(&rust_cli_bin)
            .args([
                "redis",
                &format!("127.0.0.1:{rd_port}"),
                "8",
                &n_redis.to_string(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let rd_pid = rd_cli.pid();
    let mut rd_stdout_rdr = BufReader::new(rd_cli.take_stdout().unwrap());
    {
        let mut line = String::new();
        rd_stdout_rdr.read_line(&mut line)?;
        if line.trim() != "READY" {
            return Err(OracleError::VerificationFailed(format!(
                "redis client failed ready: {line:?}"
            )));
        }
    }
    tcp.lock().unwrap().track_pid(rd_pid)?;
    {
        let mut stdin = rd_cli.take_stdin().unwrap();
        writeln!(stdin, "GO")?;
        stdin.flush()?;
    }
    let mut rd_truth_raw = String::new();
    rd_stdout_rdr.read_to_string(&mut rd_truth_raw)?;
    drop(rd_stdout_rdr);
    let rd_st = rd_cli.wait_success()?;
    stop_rd_srv.store(true, Ordering::Release);
    let _ = rd_srv_handle.join();
    if !rd_st.success() {
        return Err(OracleError::VerificationFailed(format!(
            "Redis client exited {rd_st}"
        )));
    }
    let rd_truth = parse_truth_tsv(&rd_truth_raw, L7Protocol::Redis)?;

    // Stop RingBuf drain worker and verify 0 drops before dropping probes
    stop_drain.store(true, Ordering::Release);
    let _ = drainer.join();

    let ringbuf_drops = {
        let tls_drops = tls.lock().unwrap().read_ringbuf_drops()?;
        let tcp_drops = tcp.lock().unwrap().read_ringbuf_drops()?;
        tls_drops + tcp_drops
    };
    let spans: Vec<L7Span> = reasm.lock().unwrap().drain_spans();

    drop(drain_ctx);
    drop(tls);
    drop(tcp);
    drop(reasm);

    // 5. XDP isolated veth SYN flood verification
    let xdp_drops = run_xdp_flood_check(&xdp_bpf, &dir)?;
    if xdp_drops == 0 {
        return Err(OracleError::VerificationFailed(
            "expected XDP token-bucket SYN flood drops > 0".to_owned(),
        ));
    }

    let _ = std::fs::remove_dir_all(&dir);

    let oss_spans: Vec<&L7Span> = spans
        .iter()
        .filter(|s| s.pid == oss_pid && s.protocol == L7Protocol::Http1)
        .collect();
    let go_spans: Vec<&L7Span> = spans
        .iter()
        .filter(|s| s.pid == go_pid && s.protocol == L7Protocol::Grpc)
        .collect();
    let pg_spans: Vec<&L7Span> = spans
        .iter()
        .filter(|s| s.pid == pg_pid && s.protocol == L7Protocol::Postgres)
        .collect();
    let rd_spans: Vec<&L7Span> = spans
        .iter()
        .filter(|s| s.pid == rd_pid && s.protocol == L7Protocol::Redis)
        .collect();

    let leg_oss = evaluate_leg_parity(
        L7Protocol::Http1,
        &oss_truth,
        &oss_spans,
        cfg.max_p99_delta_ms,
    )?;
    let leg_go = evaluate_leg_parity(L7Protocol::Grpc, &go_truth, &go_spans, cfg.max_p99_delta_ms)?;
    let leg_pg = evaluate_leg_parity(
        L7Protocol::Postgres,
        &pg_truth,
        &pg_spans,
        cfg.max_p99_delta_ms,
    )?;
    let leg_rd = evaluate_leg_parity(
        L7Protocol::Redis,
        &rd_truth,
        &rd_spans,
        cfg.max_p99_delta_ms,
    )?;

    let total_requested =
        leg_oss.requested + leg_go.requested + leg_pg.requested + leg_rd.requested;
    let total_recovered =
        leg_oss.recovered + leg_go.recovered + leg_pg.recovered + leg_rd.recovered;
    let total_mismatches =
        leg_oss.mismatches + leg_go.mismatches + leg_pg.mismatches + leg_rd.mismatches;

    if ringbuf_drops > 0 {
        return Err(OracleError::VerificationFailed(format!(
            "RingBuf dropped {ringbuf_drops} events"
        )));
    }

    let fds_after = open_fd_count();
    if fds_before != fds_after {
        return Err(OracleError::VerificationFailed(format!(
            "FD leak detected: before={fds_before}, after={fds_after}"
        )));
    }

    Ok(OracleReport {
        total_requested,
        total_recovered,
        total_mismatches,
        ringbuf_drops,
        go_stack_crashes,
        xdp_drops,
        elapsed_secs: overall_start.elapsed().as_secs_f64(),
        fds_before,
        fds_after,
        legs: vec![leg_oss, leg_go, leg_pg, leg_rd],
    })
}
