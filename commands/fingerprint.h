#ifndef KHM_CMD_FINGERPRINT_H
#define KHM_CMD_FINGERPRINT_H

/*
 * Fetch and print a host's live SSH fingerprint. Unlike verify, this
 * never touches known_hosts — it's the "what would TOFU show me"
 * command, useful before you've ever connected.
 */
int cmd_fingerprint(const char *host_arg, int no_color, int json_output);

#endif
