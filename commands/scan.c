#include "scan.h"
#include "../parser.h"
#include "../hostkey.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>

#define COL_RESET   "\033[0m"
#define COL_GREEN   "\033[32m"
#define COL_RED     "\033[31m"
#define COL_YELLOW  "\033[33m"
#define COL_CYAN    "\033[36m"
#define COL_DIM     "\033[2m"
#define COL_BOLD    "\033[1m"

#define MAX_HOSTS   4096
#define MAX_THREADS 64

#define C(code) (no_color ? "" : code)

/* ------------------------------------------------------------------ */
/* Host list                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    char hosts[MAX_HOSTS][256];
    int  count;
} host_list_t;

/* Parse CIDR "a.b.c.d/n" into host_list */
static int expand_cidr(const char *cidr, host_list_t *list) {
    char buf[64];
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf)-1] = '\0';

    char *slash = strchr(buf, '/');
    if (!slash) return -1;
    *slash = '\0';
    int prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) return -1;

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return -1;

    uint32_t base = ntohl(addr.s_addr);
    uint32_t mask = prefix ? (~0u << (32 - prefix)) : 0;
    uint32_t net  = base & mask;
    uint32_t bcast= net | ~mask;

    list->count = 0;
    for (uint32_t ip = net + 1; ip < bcast && list->count < MAX_HOSTS; ip++) {
        struct in_addr a;
        a.s_addr = htonl(ip);
        inet_ntop(AF_INET, &a, list->hosts[list->count++], 256);
    }
    return 0;
}

/* Read one host per line from file */
static int read_host_file(const char *path, host_list_t *list) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    list->count = 0;
    char line[256];
    while (fgets(line, sizeof(line), f) && list->count < MAX_HOSTS) {
        /* strip whitespace and comments */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        size_t n = strlen(p);
        while (n > 0 && (p[n-1] == '\n' || p[n-1] == '\r' || p[n-1] == ' '))
            p[--n] = '\0';
        if (n == 0) continue;
        snprintf(list->hosts[list->count++], 256, "%s", p);
    }
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Per-thread scan work                                                 */
/* ------------------------------------------------------------------ */

typedef enum {
    SCAN_OK = 0,
    SCAN_CHANGED,
    SCAN_NEW,
    SCAN_TIMEOUT,
    SCAN_ERROR,
} scan_status_t;

typedef struct {
    char         host[256];
    int          port;
    int          timeout_ms;
    const khm_db_t *db;        /* read-only, shared */

    /* results */
    scan_status_t status;
    char          keytype[64];
    char          fingerprint[128];
    int           no_color;
} scan_job_t;

static pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

static int db_lookup(const khm_db_t *db, const char *host, int port,
                     const char *keytype, const char *keydata_b64) {
    /* returns: 0=match, 1=key_changed, 2=not_found */
    int found_host = 0;
    int entry_port;
    for (size_t i = 0; i < db->count; i++) {
        const khm_entry_t *e = &db->entries[i];
        if (e->hashed) continue;
        entry_port = e->port ? e->port : 22;
        if (entry_port != port) continue;
        for (int j = 0; j < e->hostname_count; j++) {
            if (strcasecmp(e->hostnames[j], host) != 0) continue;
            if (strcmp(e->keytype_str, keytype) != 0) continue;
            found_host = 1;
            if (strcmp(e->keydata_b64, keydata_b64) == 0) return 0;
            return 1;
        }
    }
    return found_host ? 1 : 2;
}

static void *scan_worker(void *arg) {
    scan_job_t *job = (scan_job_t *)arg;
    int no_color = job->no_color;

    khm_hostkey_t key;
    int r = khm_fetch_hostkey(job->host, job->port, job->timeout_ms, &key);

    if (r == -2) {
        job->status = SCAN_TIMEOUT;
        pthread_mutex_lock(&print_mutex);
        printf("  %sTIMEOUT%s  %-40s\n", C(COL_DIM), C(COL_RESET), job->host);
        pthread_mutex_unlock(&print_mutex);
        return NULL;
    }
    if (r < 0) {
        job->status = SCAN_ERROR;
        /* silent — most IPs in a /24 won't have SSH */
        return NULL;
    }

    snprintf(job->keytype,     sizeof(job->keytype),     "%s", key.keytype_str);
    snprintf(job->fingerprint, sizeof(job->fingerprint), "%s", key.fingerprint);

    int lookup = db_lookup(job->db, job->host, job->port,
                           key.keytype_str, key.keydata_b64);
    if (lookup == 0) {
        job->status = SCAN_OK;
        pthread_mutex_lock(&print_mutex);
        printf("  %s✔ OK     %s  %-40s  %s%s%s  %s%s%s\n",
               C(COL_GREEN), C(COL_RESET),
               job->host,
               C(COL_CYAN), job->keytype, C(COL_RESET),
               C(COL_DIM),  job->fingerprint, C(COL_RESET));
        pthread_mutex_unlock(&print_mutex);
    } else if (lookup == 1) {
        job->status = SCAN_CHANGED;
        pthread_mutex_lock(&print_mutex);
        printf("  %s✘ CHANGED%s  %-40s  %s%s%s  %s%s%s\n",
               C(COL_RED), C(COL_RESET),
               job->host,
               C(COL_CYAN), job->keytype, C(COL_RESET),
               C(COL_DIM),  job->fingerprint, C(COL_RESET));
        pthread_mutex_unlock(&print_mutex);
    } else {
        job->status = SCAN_NEW;
        pthread_mutex_lock(&print_mutex);
        printf("  %s? NEW    %s  %-40s  %s%s%s  %s%s%s\n",
               C(COL_YELLOW), C(COL_RESET),
               job->host,
               C(COL_CYAN), job->keytype, C(COL_RESET),
               C(COL_DIM),  job->fingerprint, C(COL_RESET));
        pthread_mutex_unlock(&print_mutex);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

int cmd_scan(const char *target, const char *file, int port,
             int timeout_ms, int no_color) {
    /* resolve known_hosts */
    char default_path[512];
    if (!file) {
        khm_default_path(default_path, sizeof(default_path));
        file = default_path;
    }

    khm_db_t db = {0};
    if (khm_parse_file(file, &db) < 0) {
        fprintf(stderr, "khm scan: cannot open '%s'\n", file);
        return 1;
    }

    /* build host list */
    host_list_t *list = calloc(1, sizeof(host_list_t));
    if (!list) { khm_db_free(&db); return 1; }

    int from_cidr = (strchr(target, '/') != NULL);
    int ok;

    if (from_cidr) {
        ok = expand_cidr(target, list);
    } else {
        /* try as file first, fall back to single host */
        ok = read_host_file(target, list);
        if (ok < 0) {
            strncpy(list->hosts[0], target, 255);
            list->count = 1;
            ok = 0;
        }
    }

    if (ok < 0 || list->count == 0) {
        fprintf(stderr, "khm scan: cannot parse target '%s'\n", target);
        free(list);
        khm_db_free(&db);
        return 1;
    }

    printf("%sscan%s  %s%s%s  port %s%d%s  %d hosts\n",
           C(COL_BOLD), C(COL_RESET),
           C(COL_CYAN), target, C(COL_RESET),
           C(COL_CYAN), port,   C(COL_RESET),
           list->count);
    printf("\n");

    /* dispatch threads in batches of MAX_THREADS */
    scan_job_t *jobs = calloc((size_t)list->count, sizeof(scan_job_t));
    if (!jobs) { free(list); khm_db_free(&db); return 1; }

    int idx = 0;
    while (idx < list->count) {
        int batch = list->count - idx;
        if (batch > MAX_THREADS) batch = MAX_THREADS;

        pthread_t threads[MAX_THREADS];
        for (int i = 0; i < batch; i++) {
            scan_job_t *j = &jobs[idx + i];
            strncpy(j->host, list->hosts[idx + i], 255);
            j->port       = port;
            j->timeout_ms = timeout_ms;
            j->db         = &db;
            j->no_color   = no_color;
            pthread_create(&threads[i], NULL, scan_worker, j);
        }
        for (int i = 0; i < batch; i++)
            pthread_join(threads[i], NULL);

        idx += batch;
    }

    /* summary */
    int n_ok = 0, n_changed = 0, n_new = 0, n_timeout = 0, n_error = 0;
    for (int i = 0; i < list->count; i++) {
        switch (jobs[i].status) {
            case SCAN_OK:      n_ok++;      break;
            case SCAN_CHANGED: n_changed++; break;
            case SCAN_NEW:     n_new++;     break;
            case SCAN_TIMEOUT: n_timeout++; break;
            case SCAN_ERROR:   n_error++;   break;
        }
    }

    printf("\n%ssummary%s  ", C(COL_BOLD), C(COL_RESET));
    printf("%s%d ok%s  ", C(COL_GREEN),  n_ok,      C(COL_RESET));
    if (n_changed)
        printf("%s%d changed%s  ", C(COL_RED),    n_changed, C(COL_RESET));
    if (n_new)
        printf("%s%d new%s  ",     C(COL_YELLOW), n_new,     C(COL_RESET));
    printf("%d no-ssh\n", n_error + n_timeout);

    free(jobs);
    free(list);
    khm_db_free(&db);
    return (n_changed > 0) ? 1 : 0;
}
