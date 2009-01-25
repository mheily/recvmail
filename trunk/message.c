#include "recvmail.h"
#include "message.h"

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
    struct mail_addr *var, *nxt;

    if (msg == NULL) {
        log_debug("double message_free() detected");
        return;
    }

    free(msg->path);
    address_free(msg->sender);
    free(msg->filename);

    /* Remove all recipients from the list */
    for (var = LIST_FIRST(&msg->recipient); var != LIST_END(&msg->recipient); var = nxt) {
        nxt = LIST_NEXT(var, entries);
        address_free(var);
    }

    free(msg);
}


