#ifndef KHM_CMD_NORMALIZE_H
#define KHM_CMD_NORMALIZE_H

/*
 * Single-file cleanup only: dedupe, merge hostnames that share an
 * identical key, and sort. Deliberately does NOT touch a second file
 * (e.g. known_hosts.old) — merging across files can silently paper
 * over a real key change and is out of scope on purpose.
 *
 * write_back: 0 = print result to stdout (safe default, no file
 *             touched); 1 = atomically replace `path` with the result.
 * json_output: only affects the stdout preview (write_back==0) — when
 *             writing to a file, the file is always valid known_hosts
 *             syntax regardless of this flag.
 */
int cmd_normalize(const char *path, int write_back, int json_output);

#endif
