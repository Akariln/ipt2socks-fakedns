/* src/ev_types.h */
#ifndef IPT2SOCKS_EV_TYPES_H
#define IPT2SOCKS_EV_TYPES_H

#include "../libev/ev.h"

/* --- Application-layer type aliases for libev --- */
typedef struct ev_loop  evloop_t;
typedef struct ev_io    evio_t;
typedef struct ev_timer evtimer_t;

struct ev_watcher;
typedef void (*evio_cb_t)(evloop_t *evloop, struct ev_watcher *watcher, int revents);
typedef void (*evtimer_cb_t)(evloop_t *evloop, struct ev_watcher *watcher, int revents);

#endif
