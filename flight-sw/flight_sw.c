/*
 * SAT-1 On-Board Computer  --  cFS-style flight software  (Stage 3)
 * ------------------------------------------------------------------------
 * A teaching model of the NASA core Flight System (cFS) command path:
 *
 *   SIGNAL PASS --TCP--> [ Command Ingest ] --Software Bus--> [ app ]
 *
 * Apps are addressed on the Software Bus by their message id, which is derived
 * from the CCSDS APID. Some apps are UNRESTRICTED (telemetry, housekeeping);
 * others are PRIVILEGED and must not be reachable from a raw ground uplink.
 *
 * Two intended defects, mirroring a classic IPC-message OBC ESCAPE:
 *
 *   Stage 3a (logic):  the command router authorizes a message by indexing its
 *                      ACL with (apid & 0xFF) -- the LOW BYTE -- while routing
 *                      by the full 11-bit APID. A privileged app whose low byte
 *                      collides with an unrestricted app becomes reachable.
 *
 *   Stage 3b (memory): SANDBOX_APP copies the command payload into a fixed
 *                      stack buffer with no bounds check. Overflow the saved
 *                      return address to escape the sandboxed app and land in
 *                      the core executive routine cfe_es_privileged_exec().
 *
 * Built intentionally without stack canaries and without PIE so the challenge
 * is a fair ret2win. The firmware image (this binary, symbols intact) is
 * pulled from the GROUND ZERO operator console.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define OBC_PORT 9020

static int g_client_fd = -1;

/* ---- telemetry framing: 2-byte big-endian length prefix + payload -------- */
static void send_tm(int fd, const char *buf, uint16_t len) {
    unsigned char hdr[2] = { (unsigned char)(len >> 8), (unsigned char)(len & 0xFF) };
    write(fd, hdr, 2);
    write(fd, buf, len);
}
static void send_tm_str(int fd, const char *s) {
    send_tm(fd, s, (uint16_t)strlen(s));
}

/* ---- notify the scoreboard that the OBC has been compromised ------------- */
/* Live trigger for the 3D GUI: this is what makes SAT-1 fall out of orbit. */
static void notify_scoreboard(const char *sat_id) {
    const char *url = getenv("SCOREBOARD_URL");     /* e.g. http://scoreboard:8000 */
    const char *token = getenv("EVENT_TOKEN");
    if (!url) return;
    if (!token) token = "";

    char host[128] = "scoreboard";
    int port = 8000;
    const char *p = strstr(url, "://");
    p = p ? p + 3 : url;
    sscanf(p, "%127[^:/]:%d", host, &port);

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return;

    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s >= 0 && connect(s, res->ai_addr, res->ai_addrlen) == 0) {
        char body[256];
        int blen = snprintf(body, sizeof(body),
                            "{\"sat\":\"%s\",\"token\":\"%s\",\"event\":\"compromise\"}",
                            sat_id, token);
        char req[512];
        int rlen = snprintf(req, sizeof(req),
            "POST /api/event/compromise HTTP/1.1\r\n"
            "Host: %s\r\nContent-Type: application/json\r\n"
            "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
            host, blen, body);
        write(s, req, rlen);
    }
    if (s >= 0) close(s);
    freeaddrinfo(res);
}

/* ======================================================================== *
 *  WIN  --  core Flight Executive privileged routine.
 *  Only the boot loader is supposed to reach this. If a Software Bus message
 *  ever lands execution here, the app sandbox has been escaped.
 * ======================================================================== */
/* force_align_arg_pointer: realign RSP to 16 bytes on entry so the intended
 * ret2win works without an extra stack-alignment gadget -- otherwise entering
 * via `ret` leaves RSP off-by-8 and movaps inside libc (getaddrinfo, ...) faults. */
__attribute__((force_align_arg_pointer))
void cfe_es_privileged_exec(void) {
    const char *flag = getenv("FLAG_STAGE3B");
    const char *sat  = getenv("SAT_ID");
    if (!flag) flag = "SATCTF{local_dev_flag_3b}";
    if (!sat)  sat  = "SAT-1";

    char msg[1024];
    snprintf(msg, sizeof(msg),
        "\n[cFE_ES] *** PRIVILEGED CONTEXT ENTERED FROM SOFTWARE BUS ***\n"
        "[cFE_ES] app OBC ESCAPEd -- executing as core flight executive\n"
        "[cFE_ES] attitude control handed to uplink -- %s is DE-ORBITING\n"
        "STAGE3B %s\n", sat, flag);
    send_tm_str(g_client_fd, msg);

    notify_scoreboard(sat);   /* drop the satellite in the GUI */
    _exit(0);
}

/* ======================================================================== *
 *  SANDBOX_APP  --  "runs" an uploaded ops script inside a restricted app.
 *  VULN: unbounded copy of the command payload into a fixed stack buffer.
 * ======================================================================== */
void sandbox_exec(const unsigned char *payload, uint16_t len) {
    char script[128];
    memcpy(script, payload, len);          /* <-- Stage 3b: no bounds check */
    send_tm_str(g_client_fd,
        "SANDBOX_APP: ops script staged in exec buffer (sandbox policy: DENY syscalls)\n");
    (void)script;
}

/* ---- Software Bus app table + ACL --------------------------------------- */
struct app_t { uint16_t apid; const char *name; int restricted; };
static struct app_t APPS[] = {
    { 0x001, "HK_APP",      0 },   /* housekeeping   -- unrestricted */
    { 0x004, "TO_APP",      0 },   /* telemetry out  -- unrestricted */
    { 0x201, "CFE_ES",      1 },   /* exec services  -- PRIVILEGED   */
    { 0x204, "SANDBOX_APP", 1 },   /* ops sandbox    -- PRIVILEGED   */
};
static const int NAPPS = sizeof(APPS) / sizeof(APPS[0]);

/* acl[i] == 1  => "message id whose low byte is i may be commanded without auth" */
static unsigned char acl[256];
static void acl_init(void) {
    memset(acl, 0, sizeof(acl));
    for (int i = 0; i < NAPPS; i++)
        if (!APPS[i].restricted)
            acl[APPS[i].apid & 0xFF] = 1;   /* only unrestricted apps are opened */
}

static struct app_t *lookup(uint16_t apid) {
    for (int i = 0; i < NAPPS; i++)
        if (APPS[i].apid == apid) return &APPS[i];
    return NULL;
}

/* ---- command router ----------------------------------------------------- */
static void route(unsigned char *frame, uint16_t len) {
    if (len < 8) { send_tm_str(g_client_fd, "SB: runt packet\n"); return; }

    uint16_t apid = ((frame[0] & 0x07) << 8) | frame[1];
    int type = (frame[0] >> 4) & 1;
    int sec  = (frame[0] >> 3) & 1;
    uint8_t cmd = frame[6];

    /* secondary-header checksum (XOR of all bytes but byte 7) */
    uint8_t ck = 0;
    for (int i = 0; i < len; i++) { if (i == 7) continue; ck ^= frame[i]; }
    if (type != 1 || sec != 1 || ck != frame[7]) {
        send_tm_str(g_client_fd, "SB: malformed telecommand\n");
        return;
    }

    struct app_t *app = lookup(apid);
    if (!app) {
        char m[64]; snprintf(m, sizeof(m), "SB: no app bound to msgid 0x%03x\n", apid);
        send_tm_str(g_client_fd, m);
        return;
    }

    /* --- authorization: BUG uses the truncated low byte as the ACL index --- */
    int authorized = acl[apid & 0xFF];
    if (app->restricted && !authorized) {
        char m[96];
        snprintf(m, sizeof(m), "SB: EPERM -- %s is privileged, command authentication required\n", app->name);
        send_tm_str(g_client_fd, m);
        return;
    }

    unsigned char *payload = frame + 8;
    uint16_t paylen = len - 8;

    if (app->apid == 0x001 || app->apid == 0x004) {          /* HK / TO */
        char m[80];
        snprintf(m, sizeof(m), "%s: NOOP accepted (cmd 0x%02x)\n", app->name, cmd);
        send_tm_str(g_client_fd, m);
    } else if (app->apid == 0x201) {                          /* CFE_ES */
        const char *f3a = getenv("FLAG_STAGE3A");
        if (!f3a) f3a = "SATCTF{local_dev_flag_3a}";
        char m[256];
        snprintf(m, sizeof(m),
            "CFE_ES: privileged app reached via Software Bus (cmd 0x%02x)\n"
            "CFE_ES: NOOP ok -- cFE 6.7.0, OS_AL, PSP pc-linux\n"
            "STAGE3A %s\n", cmd, f3a);
        send_tm_str(g_client_fd, m);
    } else if (app->apid == 0x204) {                          /* SANDBOX_APP */
        sandbox_exec(payload, paylen);
    }
}

/* ---- connection handling ------------------------------------------------ */
static ssize_t readn(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r <= 0) return r;
        got += r;
    }
    return got;
}

static void handle_conn(int fd) {
    g_client_fd = fd;
    unsigned char lenhdr[2];
    if (readn(fd, lenhdr, 2) != 2) return;
    uint16_t n = (lenhdr[0] << 8) | lenhdr[1];
    if (n == 0) return;

    unsigned char *frame = malloc(n);
    if (!frame) return;
    if (readn(fd, frame, n) != n) { free(frame); return; }

    route(frame, n);
    free(frame);
}

int main(void) {
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    acl_init();
    setvbuf(stdout, NULL, _IONBF, 0);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(OBC_PORT);
    if (bind(srv, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("bind"); return 1; }
    listen(srv, 16);
    fprintf(stderr, "[flight-sw] SAT-1 OBC listening on :%d\n", OBC_PORT);

    for (;;) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) continue;
        pid_t pid = fork();
        if (pid == 0) {
            close(srv);
            handle_conn(c);
            close(c);
            _exit(0);
        }
        close(c);
    }
    return 0;
}
