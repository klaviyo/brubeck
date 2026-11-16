#include "brubeck.h"

#define INTERNAL_LONGEST_KEY ".secure.from_future"

/*
 * Mirror the per-flush internal stats to a local statsd_exporter as StatsD
 * lines. Counters are sent as |c increments so the exporter accumulates them
 * into monotonic Prometheus counters (rate() friendly); unique_keys is a gauge.
 * Best effort: UDP, non-blocking, errors ignored. Disabled unless the config
 * has a "self_statsd" block.
 */
static void
internal__emit_statsd(struct brubeck_internal_stats *stats)
{
	char buf[768];
	int n;

	if (stats->self_fd < 0)
		return;

	n = snprintf(buf, sizeof(buf),
		"%s.metrics:%u|c\n%s.errors:%u|c\n%s.unique_keys:%u|g\n"
		"%s.secure.failed:%u|c\n%s.secure.from_future:%u|c\n"
		"%s.secure.delayed:%u|c\n%s.secure.replayed:%u|c\n",
		stats->self_prefix, stats->sample.metrics,
		stats->self_prefix, stats->sample.errors,
		stats->self_prefix, stats->sample.unique_keys,
		stats->self_prefix, stats->sample.secure.failed,
		stats->self_prefix, stats->sample.secure.from_future,
		stats->self_prefix, stats->sample.secure.delayed,
		stats->self_prefix, stats->sample.secure.replayed);

	if (n > 0 && n < (int)sizeof(buf))
		sendto(stats->self_fd, buf, n, MSG_DONTWAIT,
			(struct sockaddr *)&stats->self_addr, sizeof(stats->self_addr));
}

void
brubeck_internal__sample(struct brubeck_metric *metric, brubeck_sample_cb sample, void *opaque)
{
	struct brubeck_internal_stats *stats = metric->as.other;
	uint32_t value;

	char *key = alloca(metric->key_len + strlen(INTERNAL_LONGEST_KEY) + 1);
	memcpy(key, metric->key, metric->key_len);

	WITH_SUFFIX(".metrics") {
		value = brubeck_atomic_swap(&stats->live.metrics, 0);
		stats->sample.metrics = value;
		sample(metric->type, key, (value_t)value, opaque);
	}

	WITH_SUFFIX(".errors") {
		value = brubeck_atomic_swap(&stats->live.errors, 0);
		stats->sample.errors = value;
		sample(metric->type, key, (value_t)value, opaque);
	}

	WITH_SUFFIX(".unique_keys") {
		value = brubeck_atomic_fetch(&stats->live.unique_keys);
		stats->sample.unique_keys = value;
		sample(metric->type, key, (value_t)value, opaque);
	}

	/* Secure statsd endpoint */
	WITH_SUFFIX(".secure.failed") {
		value = brubeck_atomic_swap(&stats->live.secure.failed, 0);
		stats->sample.secure.failed = value;
		sample(metric->type, key, (value_t)value, opaque);
	}

	WITH_SUFFIX(".secure.from_future") {
		value = brubeck_atomic_swap(&stats->live.secure.from_future, 0);
		stats->sample.secure.from_future = value;
		sample(metric->type, key, (value_t)value, opaque);
	}

	WITH_SUFFIX(".secure.delayed") {
		value = brubeck_atomic_swap(&stats->live.secure.delayed, 0);
		stats->sample.secure.delayed = value;
		sample(metric->type, key, (value_t)value, opaque);
	}

	WITH_SUFFIX(".secure.replayed") {
		value = brubeck_atomic_swap(&stats->live.secure.replayed, 0);
		stats->sample.secure.replayed = value;
		sample(metric->type, key, (value_t)value, opaque);
	}

	internal__emit_statsd(stats);

	/*
	 * Mark the metric as active so it doesn't get disabled
	 * by the inactive metrics pruner
	 */
	metric->expire = BRUBECK_EXPIRE_ACTIVE;
}

void brubeck_internal__init(struct brubeck_server *server)
{
	struct brubeck_metric *internal;
	struct brubeck_backend *backend;

	internal = brubeck_metric_new(server,
			server->name, strlen(server->name),
			BRUBECK_MT_INTERNAL_STATS);

	if (internal == NULL)
		die("Failed to initialize internal stats sampler");

	internal->as.other = &server->internal_stats;

	/* Optional: "self_statsd": {"address": "127.0.0.1", "port": 9125, "prefix": "brubeck_self"} */
	server->internal_stats.self_fd = -1;
	{
		json_t *ss = json_object_get(server->config, "self_statsd");
		if (ss && json_is_object(ss)) {
			const char *addr = "127.0.0.1";
			const char *prefix = "brubeck_self";
			int port = 9125;

			json_unpack(ss, "{s?:s, s?:i, s?:s}",
				"address", &addr, "port", &port, "prefix", &prefix);

			int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (fd >= 0) {
				url_to_inaddr2(&server->internal_stats.self_addr, addr, port);
				server->internal_stats.self_prefix = strdup(prefix);
				server->internal_stats.self_fd = fd;
				log_splunk("sampler=internal event=self_statsd addr=%s:%d prefix=%s",
					addr, port, prefix);
			}
		}
	}

	backend = brubeck_metric_shard(server, internal);
	server->internal_stats.sample_freq = backend->sample_freq;
}
