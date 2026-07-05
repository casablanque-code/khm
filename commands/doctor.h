#ifndef KHM_CMD_DOCTOR_H
#define KHM_CMD_DOCTOR_H

/*
 * Health check for a known_hosts file. Offline by default — only
 * check_reachable opts into live connections, so a routine "is my
 * file clean" run never needs network access.
 *
 * Exit code: 0 if no error/warning findings, 1 otherwise. "info"
 * findings (e.g. mixed_algorithms, which is often intentional) never
 * fail the run on their own.
 */
int cmd_doctor(const char *path, int no_color, int json_output, int check_reachable);

#endif
