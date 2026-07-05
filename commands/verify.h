#ifndef KHM_CMD_VERIFY_H
#define KHM_CMD_VERIFY_H

int cmd_verify(const char *host_arg, const char *file, int no_color, int json_output);

/* Verify every non-hashed host found in the known_hosts file. */
int cmd_verify_all(const char *file, int no_color, int json_output);

#endif
