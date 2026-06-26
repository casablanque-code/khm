#ifndef KHM_CMD_LIST_H
#define KHM_CMD_LIST_H

/* path = NULL → use ~/.ssh/known_hosts */
int cmd_list(const char *path, int no_color);

#endif
