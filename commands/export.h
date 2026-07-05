#ifndef KHM_CMD_EXPORT_H
#define KHM_CMD_EXPORT_H

/*
 * format: "csv", "md" (or "markdown"), "html", or "json" — case
 * insensitive. Ignored (defaults to json) if json_output is set: the
 * global --json flag always wins, same convention as every other
 * command.
 */
int cmd_export(const char *path, const char *format, int json_output);

#endif
