#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <osmocom/mslookup/mslookup_client.h>
#include <osmocom/mslookup/mslookup_client_mdns.h>
#include <osmocom/core/select.h>
#include <osmocom/core/logging.h>
#include <osmocom/mslookup/mdns.h>
#include <osmocom/mslookup/mdns_sock.h>

struct osmo_mdns_method_state {
	/* Parameters passed by _add_method_dns() */
	struct osmo_sockaddr_str bind_addr;

	struct osmo_mdns_sock *mc;

	struct osmo_mslookup_client *client;
	struct llist_head requests;
	uint16_t next_packet_id;
};

struct osmo_mdns_method_request {
	struct llist_head entry;
	uint32_t request_handle;
	struct osmo_mslookup_query query;
	uint16_t packet_id;
};

static int request_handle_by_query(uint32_t *request_handle, struct osmo_mdns_method_state *state,
				   struct osmo_mslookup_query *query, uint16_t packet_id)
{
	struct osmo_mdns_method_request *request;

	llist_for_each_entry(request, &state->requests, entry) {
		if (request->packet_id != packet_id)
			continue;
		if (strcmp(request->query.service, query->service) != 0)
			continue;
		if (osmo_mslookup_id_cmp(&request->query.id, &query->id) != 0)
			continue;

		/* Match! */
		*request_handle = request->request_handle;
		return 0;
	}
	return -1;
}

static int mdns_method_recv(struct osmo_fd *osmo_fd, unsigned int what)
{
	struct osmo_mdns_method_state *state = osmo_fd->data;
	struct osmo_mslookup_result result;
	struct osmo_mslookup_query query;
	uint16_t packet_id;
	int n;
	uint8_t buffer[1024];
	uint32_t request_handle = 0;
	void *ctx = NULL; /* FIXME */

	n = read(osmo_fd->fd, buffer, sizeof(buffer));
	if (n < 0) {
		LOGP(DLMSLOOKUP, LOGL_ERROR, "failed to read from socket\n");
		return n;
	}

	if (osmo_mdns_result_decode(ctx, buffer, n, &packet_id, &query, &result) < 0)
		return -EINVAL;

	if (request_handle_by_query(&request_handle, state, &query, packet_id) != 0)
		return -EINVAL;

	osmo_mslookup_client_rx_result(state->client, request_handle, &result);
	return n;
}

static void mdns_method_request(struct osmo_mslookup_client_method *method, const struct osmo_mslookup_query *query,
				uint32_t request_handle)
{
	char buf[100];
	struct osmo_mdns_method_state *state = method->priv;
	struct msgb *msg = msgb_alloc(1024, __func__);
	struct osmo_mdns_method_request *r = talloc_zero(method->client, struct osmo_mdns_method_request);

	*r = (struct osmo_mdns_method_request){
		.request_handle = request_handle,
		.query = *query,
		.packet_id = state->next_packet_id,
	};
	llist_add(&r->entry, &state->requests);
	state->next_packet_id++;

	osmo_mdns_query_encode(method->client, msg, r->packet_id, query);

	/* Send over the wire */
	osmo_mslookup_id_name_buf(buf, sizeof(buf), &query->id);
	LOGP(DLMSLOOKUP, LOGL_DEBUG, "sending mDNS query: how to reach %s.%s?\n", query->service, buf);
	if (osmo_mdns_sock_send(state->mc, msg) == -1) {
		LOGP(DLMSLOOKUP, LOGL_ERROR, "sending mDNS query failed!\n");
		/* TODO: do we need to call the callback now? */
	}
}

static void mdns_method_request_cleanup(struct osmo_mslookup_client_method *method, uint32_t request_handle)
{
	struct osmo_mdns_method_state *state = method->priv;

	/* Tear down any state associated with this handle. */
	struct osmo_mdns_method_request *r;
	llist_for_each_entry(r, &state->requests, entry) {
		if (r->request_handle != request_handle)
			continue;
		llist_del(&r->entry);
		talloc_free(r);
		return;
	}
}

static void mdns_method_destruct(struct osmo_mslookup_client_method *method)
{
	struct osmo_mdns_method_state *state = method->priv;
	struct osmo_mdns_method_request *e, *n;
	if (!state)
		return;

	/* Drop all DNS lookup request state. Triggering a timeout event and cleanup for mslookup client users will
	 * happen in the mslookup_client.c, we will simply stop responding from this lookup method. */
	llist_for_each_entry_safe(e, n, &state->requests, entry) {
		llist_del(&e->entry);
	}

	osmo_mdns_sock_cleanup(state->mc);
}

struct osmo_mslookup_client_method *osmo_mslookup_client_add_mdns(struct osmo_mslookup_client *client, const char *ip,
								  uint16_t port, bool reuse_addr)
{
	struct osmo_mdns_method_state *state;
	struct osmo_mslookup_client_method *m;

	m = talloc_zero(client, struct osmo_mslookup_client_method);
	OSMO_ASSERT(m);

	state = talloc_zero(m, struct osmo_mdns_method_state);
	OSMO_ASSERT(state);
	INIT_LLIST_HEAD(&state->requests);
	if (osmo_sockaddr_str_from_str(&state->bind_addr, ip, port)) {
		LOGP(DLMSLOOKUP, LOGL_ERROR, "mslookup mDNS: invalid address/port: %s %u\n",
		     ip, port);
		goto error_cleanup;
	}

	state->client = client;

	state->mc = osmo_mdns_sock_init(state, ip, port, reuse_addr, mdns_method_recv, state, 0);
	if (!state->mc)
		goto error_cleanup;

	*m = (struct osmo_mslookup_client_method){
		.name = "mDNS",
		.priv = state,
		.request = mdns_method_request,
		.request_cleanup = mdns_method_request_cleanup,
		.destruct = mdns_method_destruct,
	};

	osmo_mslookup_client_method_add(client, m);
	return m;

error_cleanup:
	talloc_free(m);
	return NULL;
}

const struct osmo_sockaddr_str *osmo_mslookup_client_method_mdns_get_bind_addr(struct osmo_mslookup_client_method
									       *dns_method)
{
	struct osmo_mdns_method_state *state;
	if (!dns_method || !dns_method->priv)
		return NULL;
	state = dns_method->priv;
	return &state->bind_addr;
}
