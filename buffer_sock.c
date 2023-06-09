#include <buffer_event.h>

static int be_socket_enable(struct bufferevent*, short);
static int be_socket_disable(struct bufferevent*, short);
static void be_socket_destruct(struct bufferevent*);
static int be_socket_flush(struct bufferevent*, short, enum bufferevent_flush_mode);
static int be_socket_ctrl(struct bufferevent*, enum bufferevent_ctrl_op, union bufferevent_ctrl_data*);

const struct bufferevent_ops bufferevent_ops_socket = {
	"socket",
	evutil_offsetof(struct bufferevent_private, bev),
	be_socket_enable,
	be_socket_disable,
	NULL, /* unlink */
	be_socket_destruct,
	NULL,//bufferevent_generic_adj_existing_timeouts_,
	be_socket_flush,
	be_socket_ctrl,
};

static int
be_socket_enable(struct bufferevent *bufev, short event)
{
	if (event & EV_READ &&
	    bufferevent_add_event_(&bufev->ev_read, &bufev->timeout_read) == -1)
			return -1;
	if (event & EV_WRITE &&
	    bufferevent_add_event_(&bufev->ev_write, &bufev->timeout_write) == -1)
			return -1;
	return 0;
}

static int
be_socket_disable(struct bufferevent *bufev, short event)
{
	if (event & EV_READ) {
		if (event_del(&bufev->ev_read) == -1)
			return -1;
	}
	struct bufferevent_private *bufev_p = BEV_UPCAST(bufev);
	if ((event & EV_WRITE) && ! bufev_p->connecting) {
		if (event_del(&bufev->ev_write) == -1)
			return -1;
	}
	return 0;
}

static void
be_socket_destruct(struct bufferevent *bufev)
{

}

static int
be_socket_flush(struct bufferevent *bev, short iotype,
    enum bufferevent_flush_mode mode)
{
	return 0;
}

static int
be_socket_ctrl(struct bufferevent *bev, enum bufferevent_ctrl_op op,
    union bufferevent_ctrl_data *data)
{
	switch (op) {

	default:
		return -1;
	}
}

static void
bufferevent_readcb(evutil_socket_t fd, short event, void* arg)
{

}

static void
bufferevent_writecb(evutil_socket_t fd, short event, void* arg)
{
	struct bufferevent *bufev = arg;
	struct bufferevent_private *bufev_p = BEV_UPCAST(bufev);
	++bufev_p->refcnt;

	short what = BEV_EVENT_WRITING;
	if (event == EV_TIMEOUT) {
		what |= BEV_EVENT_TIMEOUT;
		goto error;
	}
	int connected = 0;
	if (bufev_p->connecting) {

	}

	if (bufev_p->write_suspended)
		goto done;

	int res = 0;
	//ev_ssize_t atmost = bufferevent_get_write_max_(bufev_p);

	if (evbuffer_get_length(bufev->output)) {
		evbuffer_unfreeze(bufev->output, 1);
		res = evbuffer_write_atmost(bufev->output, fd, -1);
		evbuffer_freeze(bufev->output, 1);
		if (res == -1) {
			//int err = evutil_socket_geterror(fd);
			//if (EVUTIL_ERR_RW_RETRIABLE(err))
			//	goto reschedule;
			what |= BEV_EVENT_ERROR;
		} 
		else if (res == 0) {
			what |= BEV_EVENT_EOF;
		}
		if (res <= 0)
			goto error;

		//bufferevent_decrement_write_buckets_(bufev_p, res);
	}
	if (evbuffer_get_length(bufev->output) == 0) {
		event_del(&bufev->ev_write);
	}

	if (res || !connected) {
		bufferevent_trigger_nolock_(bufev, EV_WRITE, 0);
	}
	goto done;

 reschedule:
	if (evbuffer_get_length(bufev->output) == 0) {
		event_del(&bufev->ev_write);
	}
	goto done;

 error:
	bufferevent_disable(bufev, EV_WRITE);
	//bufferevent_run_eventcb_(bufev, what, 0);

 done:
	--bufev_p->refcnt;
}

int
evbuffer_write_atmost(struct evbuffer* buffer, evutil_socket_t fd,
	ev_ssize_t howmuch)
{
	if (buffer->freeze_start) {
		goto done;
	}

	int n = -1;
	if (howmuch < 0 || (size_t)howmuch > buffer->total_len)
		howmuch = buffer->total_len;
	if (howmuch > 0) {
#ifdef USE_IOVEC_IMPL
		n = evbuffer_write_iovec(buffer, fd, howmuch);
#elif defined(_WIN32)
		void *p = evbuffer_pullup(buffer, howmuch);
		n = send(fd, p, howmuch, 0);
#else
		void *p = evbuffer_pullup(buffer, howmuch);
		n = write(fd, p, howmuch);
#endif
	}

	if (n > 0)
		evbuffer_drain(buffer, n);

done:
	return (n);
}

static struct evbuffer_chain*
evbuffer_chain_new(size_t size)
{
	if (size > UINT64_MAX - EVBUFFER_CHAIN_SIZE)
		return (NULL);

	size += EVBUFFER_CHAIN_SIZE;
	size_t to_alloc;
	if (size < UINT64_MAX / 2) {
		to_alloc = MIN_BUFFER_SIZE;
		while (to_alloc < size) {
			to_alloc <<= 1;
		}
	}
	else {
		to_alloc = size;
	}

	struct evbuffer_chain* chain = malloc(to_alloc);
	memset(chain, 0, EVBUFFER_CHAIN_SIZE);
	chain->buffer = EVBUFFER_CHAIN_EXTRA(unsigned char, chain);
	chain->buffer_len = to_alloc - EVBUFFER_CHAIN_SIZE;
	chain->refcnt = 1;

	return (chain);
}

unsigned char *
evbuffer_pullup(struct evbuffer *buf, ev_ssize_t size)
{
	unsigned char *result = NULL;

	if (size < 0)
		size = buf->total_len;
	if (size == 0 || (size_t)size > buf->total_len)
		goto done;
	struct evbuffer_chain *chain = buf->first;
	if (chain->off >= (size_t)size) {
		result = chain->buffer + chain->misalign;
		goto done;
	}

	struct evbuffer_chain *tmp;
	ev_ssize_t remaining = size - chain->off;
	for (tmp=chain->next; tmp; tmp=tmp->next) {
		if (CHAIN_PINNED(tmp))
			goto done;
		if (tmp->off >= (size_t)remaining)
			break;
		remaining -= tmp->off;
	}

	/** ÕæÊµ×Ö·û´® */
	unsigned char *buffer;
	if (CHAIN_PINNED(chain)) {
		//
		chain = chain->next;
	}
	else if (chain->buffer_len - chain->misalign >= (size_t)size) {
		//
	}
	else {
		if ((tmp = evbuffer_chain_new(size)) == NULL)
			goto done;
		buffer = tmp->buffer;
		tmp->off = size;
		buf->first = tmp;
	}

	struct evbuffer_chain *last_with_data = *buf->last_with_datap, *next;
	int removed_last_with_data = 0;
	int removed_last_with_datap = 0;
	for (; chain != NULL && (size_t)size >= chain->off; chain = next) {
		next = chain->next;

		if (chain->buffer) {
			memcpy(buffer, chain->buffer + chain->misalign, chain->off);
			size -= chain->off;
			buffer += chain->off;
		}
		if (chain == last_with_data)
			removed_last_with_data = 1;
		if (&chain->next == buf->last_with_datap)
			removed_last_with_datap = 1;

		evbuffer_chain_free(chain);
	}

	if (chain != NULL) {
		memcpy(buffer, chain->buffer + chain->misalign, size);
		chain->misalign += size;
		chain->off -= size;
	}
	else {
		buf->last = tmp;
	}

	tmp->next = chain;

	if (removed_last_with_data) {
		buf->last_with_datap = &buf->first;
	}
	else if (removed_last_with_datap) {
		if (buf->first->next && buf->first->next->off)
			buf->last_with_datap = &buf->first->next;
		else
			buf->last_with_datap = &buf->first;
	}

	result = (tmp->buffer + tmp->misalign);

done:
	return result;
}

static inline int
HAS_PINNED_R(struct evbuffer *buf)
{
	return (buf->last && CHAIN_PINNED_R(buf->last));
}

int
evbuffer_drain(struct evbuffer *buf, size_t len)
{
	int result = 0;

	size_t old_len = buf->total_len;
	if (old_len == 0)
		goto done;
	if (buf->freeze_start) {
		result = -1;
		goto done;
	}

	if (len >= old_len && !HAS_PINNED_R(buf)) {
		//
	}
	else {
		if (len >= old_len)
			len = old_len;

		buf->total_len -= len;
		size_t remaining = len;
		struct evbuffer_chain *chain, *next;

		for (chain = buf->first; remaining >= chain->off; chain = next) {
			next = chain->next;
			remaining -= chain->off;

			if (&chain->next == buf->last_with_datap || 
				chain == *buf->last_with_datap ) {
				buf->last_with_datap = &buf->first;
			}

			if (CHAIN_PINNED_R(chain)) {
				chain->misalign += chain->off;
				chain->off = 0;
				break;
			}
			else {
				evbuffer_chain_free(chain);
			}
		}

		buf->first = chain;
		chain->misalign += remaining;
		chain->off -= remaining;
	}

	buf->n_del_for_cb += len;
	evbuffer_invoke_callbacks_(buf);

done:
	return result;
}

void
bufferevent_run_readcb_(struct bufferevent *bufev, int options)
{
	if (bufev->readcb == NULL)
		return;
	struct bufferevent_private *p = BEV_UPCAST(bufev);
	if ((p->options|options) & BEV_OPT_DEFER_CALLBACKS) {
		//p->readcb_pending = 1;
		//SCHEDULE_DEFERRED(p);
	} else {
		bufev->readcb(bufev, bufev->cbarg);
		//bufferevent_inbuf_wm_check(bufev);
	}
}

void
bufferevent_run_writecb_(struct bufferevent *bufev, int options)
{
	if (bufev->writecb == NULL)
		return;
	struct bufferevent_private *p = BEV_UPCAST(bufev);
	if ((p->options|options) & BEV_OPT_DEFER_CALLBACKS) {
		//p->writecb_pending = 1;
		//SCHEDULE_DEFERRED(p);
	} else {
		bufev->writecb(bufev, bufev->cbarg);
	}
}

static void
bufferevent_socket_outbuf_cb(struct evbuffer *buf,
    const struct evbuffer_cb_info *cbinfo, void *arg)
{
	struct bufferevent *bufev = arg;
	struct bufferevent_private *bufev_p = BEV_UPCAST(bufev);

	if (cbinfo->n_added &&
	    (bufev->enabled & EV_WRITE) &&
	    !event_pending(&bufev->ev_write, EV_WRITE, NULL) &&
	    !bufev_p->write_suspended) {

		if (bufferevent_add_event_(&bufev->ev_write, &bufev->timeout_write) == -1) {
		    /* Should we log this? */
		}
	}
}

struct bufferevent *
bufferevent_socket_new(struct event_base *base, evutil_socket_t fd, int options)
{
#ifdef _WIN32
    //IOCP
#endif
    struct bufferevent_private* bufev_p = calloc(1, sizeof(struct bufferevent_private));
    if (bufev_p == NULL)
        return NULL;
    if (bufferevent_init_common_(bufev_p, base, &bufferevent_ops_socket, options) < 0) {
        free(bufev_p);
        return NULL;
    }

    struct bufferevent* bufev = &bufev_p->bev;

	/** ³õÊ¼»¯¶ÁÐ´ÊÂ¼þ */
	event_assign(&bufev->ev_read, bufev->ev_base, fd,
	    EV_READ|EV_PERSIST|EV_FINALIZE, bufferevent_readcb, bufev);
	event_assign(&bufev->ev_write, bufev->ev_base, fd,
	    EV_WRITE|EV_PERSIST|EV_FINALIZE, bufferevent_writecb, bufev);

	evbuffer_set_flags(bufev->output, EVBUFFER_FLAG_DRAINS_TO_FD);
	evbuffer_add_cb(bufev->output, bufferevent_socket_outbuf_cb, bufev);

	evbuffer_freeze(bufev->input, 0);
	evbuffer_freeze(bufev->output, 1);

    return bufev;
}

struct evbuffer_cb_entry*
evbuffer_add_cb(struct evbuffer* buffer, evbuffer_cb_func cb, void* cbarg)
{
	struct evbuffer_cb_entry* e = calloc(1, sizeof(struct evbuffer_cb_entry));
	if (e == NULL)
		return NULL;
	e->cb.cb_func = cb;
	e->cbarg = cbarg;
	e->flags = EVBUFFER_CB_ENABLED;
	LIST_INSERT_HEAD(&buffer->callbacks, e, next);
	return e;
}

static void
bufferevent_run_deferred_callbacks_unlocked(struct event_callback* cb, void* arg)
{
	struct bufferevent_private *bufev_private = arg;
	struct bufferevent* bufev = &bufev_private->bev;

	void* cbarg = bufev->cbarg;
	if ((bufev_private->eventcb_pending & BEV_EVENT_CONNECTED) && bufev->errorcb) {
		bufev_private->eventcb_pending &= ~BEV_EVENT_CONNECTED;
		bufev->errorcb(bufev, BEV_EVENT_CONNECTED, cbarg);
	}
	if (bufev_private->readcb_pending && bufev->readcb) {
		bufev_private->readcb_pending = 0;
		bufev->readcb(bufev, cbarg);
	}
	if (bufev_private->writecb_pending && bufev->writecb) {
		bufev_private->writecb_pending = 0;
		bufev->writecb(bufev, cbarg);
	}
	if (bufev_private->eventcb_pending && bufev->errorcb) {
		short what = bufev_private->eventcb_pending;
		bufev_private->eventcb_pending = 0;
		bufev->errorcb(bufev, what, cbarg);
	}
	--bufev_private->refcnt;
	//bufferevent_decref_and_unlock_(bufev);
}

static void
bufferevent_run_deferred_callbacks_locked(struct event_callback* cb, void* arg)
{
	bufferevent_run_deferred_callbacks_unlocked(cb, arg);
}

int
bufferevent_init_common_(struct bufferevent_private* bufev_private,
    struct event_base* base, const struct bufferevent_ops* ops,
    enum bufferevent_options options)
{
    struct bufferevent* bufev = &bufev_private->bev;

	if (!bufev->input) {
		if ((bufev->input = evbuffer_new()) == NULL)
			goto err;
	}
	if (!bufev->output) {
		if ((bufev->output = evbuffer_new()) == NULL)
			goto err;
	}

	bufev_private->refcnt = 1;
	bufev->be_ops = ops;
	bufev->ev_base = base;
	timerclear(&bufev->timeout_read);
	timerclear(&bufev->timeout_write);

	//if (bufferevent_ratelim_init_(bufev_private))
	//	goto err;

	bufev->enabled = EV_WRITE;

	if ((options & (BEV_OPT_DEFER_CALLBACKS | BEV_OPT_UNLOCK_CALLBACKS))
		== BEV_OPT_UNLOCK_CALLBACKS) {
		goto err;
	}
	if (options & BEV_OPT_UNLOCK_CALLBACKS)
		event_deferred_cb_init_(
			&bufev_private->deferred,
			base->nactivequeues / 2,
			bufferevent_run_deferred_callbacks_unlocked,
			bufev_private);
	else
		event_deferred_cb_init_(
			&bufev_private->deferred,
			base->nactivequeues / 2,
			bufferevent_run_deferred_callbacks_locked,
			bufev_private);

	bufev_private->options = options;
	struct evbuffer* inbuf = bufev->input;
	inbuf->parent = bufev;
	struct evbuffer* outbuf = bufev->input;
	outbuf->parent = bufev;

    return 0;

err:
	if (bufev->input) {
		evbuffer_free(bufev->input);
		bufev->input = NULL;
	}
	if (bufev->output) {
		evbuffer_free(bufev->output);
		bufev->output = NULL;
	}
    return -1;
}

struct evbuffer *
evbuffer_new(void)
{
	struct evbuffer *buffer = calloc(1, sizeof(struct evbuffer));
	if (buffer == NULL)
		return (NULL);

	LIST_INIT(&buffer->callbacks);
	buffer->refcnt = 1;
	buffer->last_with_datap = &buffer->first;

	return (buffer);
}

static void
evbuffer_remove_all_callbacks(struct evbuffer* buffer)
{
	struct evbuffer_cb_entry* cbent;

	while ((cbent = LIST_FIRST(&buffer->callbacks))) {
		LIST_REMOVE(cbent, next);
		free(cbent);
	}
}

void
evbuffer_free(struct evbuffer* buffer)
{
	if (buffer->refcnt <= 0 || --buffer->refcnt > 0)
		return;

	struct evbuffer_chain *chain, *next;
	for (chain = buffer->first; chain != NULL; chain = next) {
		next = chain->next;
		evbuffer_chain_free(chain);
	}
	evbuffer_remove_all_callbacks(buffer);

	if (buffer->deferred_cbs)
		event_callback_cancel_nolock_(buffer->cb_queue, &buffer->deferred, 0);

	free(buffer);
}

int
bufferevent_add_event_(struct event* ev, const struct timeval* tv)
{
	if (!timerisset(tv))
		return event_add(ev, NULL);
	else
		return event_add(ev, tv);
}

int
evbuffer_freeze(struct evbuffer* buffer, int start)
{
	if (start)
		buffer->freeze_start = 1;
	else
		buffer->freeze_end = 1;
	return 0;
}

int
evbuffer_unfreeze(struct evbuffer* buffer, int start)
{
	if (start)
		buffer->freeze_start = 0;
	else
		buffer->freeze_end = 0;
	return 0;
}

void
bufferevent_setcb(struct bufferevent* bufev,
	bufferevent_data_cb readcb, bufferevent_data_cb writecb,
	bufferevent_event_cb eventcb, void* cbarg)
{
	bufev->readcb = readcb;
	bufev->writecb = writecb;
	bufev->errorcb = eventcb;

	bufev->cbarg = cbarg;
}

int
bufferevent_enable(struct bufferevent* bufev, short event)
{
	struct bufferevent_private* bufev_private = BEV_UPCAST(bufev);
	++bufev_private->refcnt;

	short impl_events = event;
	if (bufev_private->read_suspended)
		impl_events &= ~EV_READ;
	if (bufev_private->write_suspended)
		impl_events &= ~EV_WRITE;

	bufev->enabled |= event;

	int r = 0;
	if (impl_events && bufev->be_ops->enable(bufev, impl_events) < 0)
		r = -1;

	--bufev_private->refcnt;
	//bufferevent_decref_and_unlock_(bufev);
	return r;
}

int
bufferevent_disable(struct bufferevent* bufev, short event)
{
	bufev->enabled &= ~event;

	int r = 0;
	if (bufev->be_ops->disable(bufev, event) < 0)
		r = -1;

	return r;
}

int
bufferevent_write(struct bufferevent* bufev, const void* data, size_t size)
{
	if (evbuffer_add(bufev->output, data, size) == -1)
		return (-1);

	return 0;
}

#define MAX_TO_REALIGN_IN_EXPAND 2048

static int
evbuffer_chain_should_realign(struct evbuffer_chain *chain,
    size_t datlen)
{
	return chain->buffer_len - chain->off >= datlen &&
	    (chain->off < chain->buffer_len / 2) &&
	    (chain->off <= MAX_TO_REALIGN_IN_EXPAND);
}

static void
evbuffer_chain_align(struct evbuffer_chain* chain)
{
	memmove(chain->buffer, chain->buffer + chain->misalign, chain->off);
	chain->misalign = 0;
}



static void
evbuffer_free_all_chains(struct evbuffer_chain* chain)
{
	struct evbuffer_chain* next;
	for (; chain; chain = next) {
		next = chain->next;
		evbuffer_chain_free(chain);
	}
}

static struct evbuffer_chain**
evbuffer_free_trailing_empty_chains(struct evbuffer* buf)
{
	struct evbuffer_chain** ch = buf->last_with_datap;
	while ((*ch) && ((*ch)->off != 0 || CHAIN_PINNED(*ch)))
		ch = &(*ch)->next;
	if (*ch) {
		evbuffer_free_all_chains(*ch);
		*ch = NULL;
	}
	return ch;
}

static void
evbuffer_chain_insert(struct evbuffer* buf,
	struct evbuffer_chain* chain)
{
	if (*buf->last_with_datap == NULL) {
		buf->first = buf->last = chain;
	}
	else {
		struct evbuffer_chain** chp;
		chp = evbuffer_free_trailing_empty_chains(buf);
		*chp = chain;
		if (chain->off)
			buf->last_with_datap = chp;
		buf->last = chain;
	}
	buf->total_len += chain->off;
}

#define EVBUFFER_CHAIN_MAX_AUTO_SIZE 4096

int
evbuffer_add(struct evbuffer* buf, const void* data_in, size_t datlen)
{
	int result = -1;

	if (buf->freeze_end) {
		goto done;
	}
	if (datlen > UINT64_MAX - buf->total_len) {
		goto done;
	}

	struct evbuffer_chain* chain;
	if (*buf->last_with_datap == NULL) {
		chain = buf->last;
	}
	else {
		chain = *buf->last_with_datap;
	}

	/** ÉêÇëchain¿Õ¼ä */
	if (chain == NULL) {
		chain = evbuffer_chain_new(datlen);
		if (!chain)
			goto done;
		evbuffer_chain_insert(buf, chain);
	}

	size_t remain;
	const unsigned char* data = data_in;

	if (!(chain->flags & EVBUFFER_IMMUTABLE)) {
		remain = chain->buffer_len - (size_t)chain->misalign - chain->off;
		if (remain >= datlen) {
			memcpy(chain->buffer + chain->misalign + chain->off,
				data, datlen);
			chain->off += datlen;
			buf->total_len += datlen;
			buf->n_add_for_cb += datlen;
			goto out;
		}
		else if (!CHAIN_PINNED(chain) &&
			evbuffer_chain_should_realign(chain, datlen)) {
			evbuffer_chain_align(chain);
			memcpy(chain->buffer + chain->off, data, datlen);
			chain->off += datlen;
			buf->total_len += datlen;
			buf->n_add_for_cb += datlen;
			goto out;
		}
	}
	else {
		remain = 0;
	}

	if (remain) {
		memcpy(chain->buffer + chain->misalign + chain->off,
			data, remain);
		chain->off += remain;
		buf->total_len += remain;
		buf->n_add_for_cb += remain;
	}
	data += remain;
	datlen -= remain;

	size_t to_alloc = chain->buffer_len;
	if (to_alloc <= EVBUFFER_CHAIN_MAX_AUTO_SIZE / 2)
		to_alloc <<= 1;
	if (datlen > to_alloc)
		to_alloc = datlen;

	/** ÉêÇëÁÙÊ±»º³åÇø */
	struct evbuffer_chain* tmp = evbuffer_chain_new(to_alloc);
	if (tmp == NULL)
		goto done;

	memcpy(tmp->buffer, data, datlen);
	tmp->off = datlen;
	evbuffer_chain_insert(buf, tmp);
	buf->n_add_for_cb += datlen;

out:
	evbuffer_invoke_callbacks_(buf);
	result = 0;
done:
	return result;
}

static void
evbuffer_run_callbacks(struct evbuffer* buffer, int running_deferred)
{
	uint32_t mask, masked_val;
	int clear = 1;

	if (running_deferred) {

	}
	else if (buffer->deferred_cbs) {
		clear = 0;
	}
	else {
		mask = EVBUFFER_CB_ENABLED;
		masked_val = EVBUFFER_CB_ENABLED;
	}

	if (LIST_EMPTY(&buffer->callbacks)) {
		buffer->n_add_for_cb = buffer->n_del_for_cb = 0;
		return;
	}
	if (buffer->n_add_for_cb == 0 && buffer->n_del_for_cb == 0)
		return;

	if (clear) {
		buffer->n_add_for_cb = 0;
		buffer->n_del_for_cb = 0;
	}

	struct evbuffer_cb_entry *cbent, *next;
	struct evbuffer_cb_info info;
	size_t new_size = buffer->total_len;
	info.orig_size = new_size + buffer->n_del_for_cb - buffer->n_add_for_cb;
	info.n_added = buffer->n_add_for_cb;
	info.n_deleted = buffer->n_del_for_cb;

	for (cbent = LIST_FIRST(&buffer->callbacks);
		cbent != LIST_END(&buffer->callbacks);
		cbent = next) {

		next = LIST_NEXT(cbent, next);
		if ((cbent->flags & mask) != masked_val)
			continue;

		if ((cbent->flags & EVBUFFER_CB_OBSOLETE))
			cbent->cb.cb_obsolete(buffer,
				info.orig_size, new_size, cbent->cbarg);
		else
			cbent->cb.cb_func(buffer, &info, cbent->cbarg);
	}
}

void
evbuffer_invoke_callbacks_(struct evbuffer* buffer)
{
	if (LIST_EMPTY(&buffer->callbacks)) {
		buffer->n_add_for_cb = buffer->n_del_for_cb = 0;
		return;
	}

	if (buffer->deferred_cbs) {
		//if (event_deferred_cb_schedule_(buffer->cb_queue, &buffer->deferred)) {
		//	evbuffer_incref_and_lock_(buffer);
		//	if (buffer->parent)
		//		bufferevent_incref_(buffer->parent);
		//	EVBUFFER_UNLOCK(buffer);
		//}
	}

	evbuffer_run_callbacks(buffer, 0);
}

void
bufferevent_free(struct bufferevent *bufev)
{
	bufferevent_setcb(bufev, NULL, NULL, NULL, NULL);
	//bufferevent_cancel_all_(bufev);
	//bufferevent_decref_and_unlock_(bufev);
}