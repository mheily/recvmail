#include "recvmail.h"

struct message *
message_new()
{
    struct message *msg;

    if ((msg = calloc(1, sizeof(struct message))) == NULL) {
        /* TODO: log_err() */
        return (NULL);
    }

    LIST_INIT(&msg->recipient);
    return (msg);
}

void
message_free(struct message *msg)
{
    if (msg) {
        free(msg->path);
        free(msg->sender);
        free(msg->filename);
        /* XXX-FIXME free recipient list */
        free(msg);
    }
}


