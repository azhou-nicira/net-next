/*
 * Copyright (c) 2017 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/seqlock.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables.h>

enum meter_result {
	METER_ACCEPT,
	METER_DROP,
	METER_DSCP,
};

struct nft_meter_stats {
	atomic64_t n_packets;
	atomic64_t n_bytes;
};

struct nft_meter_band {
	u64 rate;               /* packets or bits/s */
	u64 ps_rate;            /* per second rate, for comparing rates
				   across bands. */
	u64 nsecs;		/* ??? */
	u64 burst;		/* ???? */
	u64 tokens;		/* ???? */
	u64 tokens_max;		/* ???? */
	u64 cost;               /* Pre computed per packet unit cost. */
	u32 type;		/* ???? */
	struct nft_meter_stats stats;
};

struct nft_meter {
	spinlock_t	lock;
	u64		last;		/* Time stamp (in nsecs) that the
					   meter was last visited. */
	u32		flags;          /* enum nft_meter_type_flags. */
	int		n_bands;
	struct nft_meter_stats stats;
	struct nft_meter_band *bands;
};

static int nft_meter_band_init(struct nft_meter_band *band,
			       struct nlattr *tb[])
{
	u64 unit, n_bytes, n_packets, bucket;

	if (tb[NFTA_METER_BAND_RATE] == NULL ||
	    tb[NFTA_METER_BAND_UNIT] == NULL ||
	    tb[NFTA_METER_BAND_TYPE] == NULL)
		return -EINVAL;

	band->type = be32_to_cpu(nla_get_be32(tb[NFTA_METER_BAND_TYPE]));
	band->rate = be64_to_cpu(nla_get_be64(tb[NFTA_METER_BAND_RATE]));
	unit = be64_to_cpu(nla_get_be64(tb[NFTA_METER_BAND_UNIT]));
	band->nsecs = unit * NSEC_PER_SEC;

	if (band->rate == 0 || band->nsecs < unit)
		return -EOVERFLOW;

	if (tb[NFTA_METER_BAND_BURST])
		band->burst = be64_to_cpu(nla_get_be64(tb[NFTA_METER_BAND_BURST]));
	else
		band->burst = band->rate;   /* Default burst = rate */

	bucket = band->rate + band->burst;
	if (bucket  < band->rate)
		return -EOVERFLOW;

	band->tokens = div64_u64(bucket * band->nsecs, band->rate);
	band->tokens_max = band->tokens;

	band->ps_rate = div64_u64(band->rate * NSEC_PER_SEC, unit);

	if (tb[NFTA_METER_BAND_BYTES])
		n_bytes = be64_to_cpu(nla_get_be64(tb[NFTA_METER_BAND_BYTES]));
	else
		n_bytes = 0;

	if (tb[NFTA_METER_BAND_PACKETS])
		n_packets = be64_to_cpu(nla_get_be64(tb[NFTA_METER_BAND_PACKETS]));
	else
		n_packets = 0;

	atomic64_set(&band->stats.n_bytes, n_bytes);
	atomic64_set(&band->stats.n_packets, n_packets);

	band->cost = div64_u64(band->nsecs, band->rate);
	return 0;
}

static const struct nla_policy nft_meter_band_policy[NFTA_METER_BAND_MAX + 1] = {
	[NFTA_METER_BAND_BYTES]	= { .type = NLA_U64 },
	[NFTA_METER_BAND_PACKETS]= { .type = NLA_U64 },
	[NFTA_METER_BAND_RATE]	= { .type = NLA_U64 },
	[NFTA_METER_BAND_UNIT]	= { .type = NLA_U64 },
	[NFTA_METER_BAND_BURST]	= { .type = NLA_U64 },
	[NFTA_METER_BAND_TYPE]	= { .type = NLA_U32 },
};

static int nft_meter_band_do_init(const struct nlattr *battr,
				  struct nft_meter_band *band)
{
	struct nlattr *tb[NFTA_METER_BAND_MAX + 1];
	int ret;

	ret = nla_parse_nested(tb, NFTA_METER_BAND_MAX,
			       battr, nft_meter_band_policy, NULL);
	if (ret < 0)
		return ret;

	return nft_meter_band_init(band, tb);
}

static int nft_meter_do_init(const struct nlattr *const tb[],
			     struct nft_meter *meter)
{
	struct nlattr *battr;
	int len;
	int n_bands;
	struct nft_meter_band *bands;
	int ret = 0;

	atomic64_set(&meter->stats.n_packets, 0);
	atomic64_set(&meter->stats.n_bytes, 0);
	spin_lock_init(&meter->lock);

	if (tb[NFTA_METER_FLAGS] == NULL ||
		(tb[NFTA_METER_BANDS] == tb[NFTA_METER_BAND]
		 && tb[NFTA_METER_BAND] == NULL))
		/* Empty meter, packets are not metered. The meter is
		 * effectively a coutner */
		goto empty;

	meter->flags = be32_to_cpu(nla_get_be32(tb[NFTA_METER_FLAGS]));


	/* Count number of bands */
	if (tb[NFTA_METER_BANDS]) {
		battr = nla_find_nested(tb[NFTA_METER_BANDS], NFTA_METER_BAND);
		len = tb[NFTA_METER_BANDS]->nla_len;
		for (n_bands = 0; len > 0;
			battr = nla_next(battr, &len), n_bands++);
	} else {
		n_bands = 1;
	}

	/* Allocate memory for bands */
	bands = kmalloc(sizeof(*bands) * n_bands, GFP_KERNEL);
	if (!bands) {
		return -ENOMEM;
	}

	/* Init bands */
	if (tb[NFTA_METER_BAND]) {
		ret = nft_meter_band_do_init(tb[NFTA_METER_BAND], bands);
		if (ret) {
			goto err;
		}
	} else {
		battr = nla_find_nested(tb[NFTA_METER_BANDS], NFTA_METER_BAND);
		len = tb[NFTA_METER_BANDS]->nla_len;
		for (n_bands = 0; len > 0; battr = nla_next(battr, &len), n_bands++) {
			ret = nft_meter_band_do_init(battr, &bands[n_bands]);
			if (ret)
				goto err;
		}
	}

	meter->bands = bands;
	meter->n_bands = n_bands;
	meter->last = ktime_get_ns();
	return 0;

err:
	kfree(bands);
empty:
	meter->flags = 0;
	meter->bands = NULL;
	meter->n_bands = 0;
	return ret;
}

static bool nft_meter_band_eval(struct nft_meter_band *band, u64 tokens,
				u64 cost)
{
	s64 delta;
	bool drop;

	tokens += band->tokens;
	if (band->tokens_max < tokens) {
		tokens = band->tokens_max;
	}

	delta = (s64)tokens -(s64)cost;
	drop = !!(delta < 0);

	/* Maintain per band token count. */
	band->tokens = drop ? tokens : delta;
	return  drop;
}

/* Maintain drop stats for Band */
static void nft_meter_band_drop(struct nft_meter_band *band, u32 packet_size)
{
	atomic64_add(1, &band->stats.n_packets);
	atomic64_add(packet_size, &band->stats.n_bytes);
}

/* Return wheter the meter should drop the packet */
static enum meter_result __nft_meter_do_eval(struct nft_meter *meter,
                                             u32 packet_size)
{
	u64 now, new_tokens;
	int drop_band;
	u64 max_rate;
	bool drop;
	int i;
	enum meter_result result;

	if (!meter->n_bands)
		return false;

	spin_lock_bh(&meter->lock);
	now = ktime_get_ns();
	new_tokens = now - meter->last;

	max_rate = 0;
	drop_band = 0;
	drop = false;

	for (i = 0; i < meter->n_bands; i++) {
		u64 cost = meter->bands[i].cost;
		cost = (meter->flags & NFT_METER_F_PPS) ? cost
							: cost * packet_size;

		if (nft_meter_band_eval(&meter->bands[i], new_tokens, cost)) {
			if (max_rate < meter->bands[i].ps_rate) {
				max_rate = meter->bands[i].ps_rate;
				drop_band = i;
			}
			drop = true;
		}
	}

	meter->last = now;
	spin_unlock_bh(&meter->lock);

	if (drop) {
		struct nft_meter_band *band;

		band = &meter->bands[drop_band];
		nft_meter_band_drop(band,  packet_size);
		if (band->type == NFT_METER_BAND_TYPE_DSCP)
			result = METER_DSCP;
		else
			result = METER_DROP;
	} else {
		result = METER_ACCEPT;
	}

	return result;
}

static void nft_meter_do_eval(struct nft_meter *meter,
			      struct nft_regs *regs,
			      const struct nft_pktinfo *pkt)
{
	u32 packet_size = pkt->skb->len;
	enum meter_result result;

	atomic64_add(1, &meter->stats.n_packets);
	atomic64_add(packet_size, &meter->stats.n_bytes);

	result = __nft_meter_do_eval(meter, packet_size);
	if (result == METER_DROP)
		regs->verdict.code = NFT_BREAK;
}

static int nft_meter_band_do_dump(struct sk_buff *skb,
				  struct nft_meter_band *band, bool reset)
{
	struct nlattr *battr;
	u64 n_packets, n_bytes, unit;

	n_packets = atomic64_read(&band->stats.n_packets);
	n_bytes = atomic64_read(&band->stats.n_bytes);
	battr = nla_nest_start(skb, NFTA_METER_BAND);
	if (!battr)
		goto nla_put_failure;

	unit = band->nsecs / NSEC_PER_SEC;

	if (nla_put_be64(skb, NFTA_METER_BAND_RATE, cpu_to_be64(band->rate),
			 NFTA_COUNTER_PAD) ||
	    nla_put_be64(skb, NFTA_METER_BAND_UNIT, cpu_to_be64(unit),
			 NFTA_COUNTER_PAD) ||
	    nla_put_be32(skb, NFTA_METER_BAND_TYPE,
			 cpu_to_be32(band->type)) ||
	    nla_put_be64(skb, NFTA_METER_BAND_BYTES, cpu_to_be64(n_bytes),
			 NFTA_COUNTER_PAD) ||
	    nla_put_be64(skb, NFTA_METER_BAND_PACKETS, cpu_to_be64(n_packets),
			 NFTA_COUNTER_PAD))
		goto nla_put_failure;

	    if (band->burst &&
		nla_put_be64(skb, NFTA_METER_BAND_BURST,
			     cpu_to_be64(band->burst), NFTA_COUNTER_PAD))
		goto nla_put_failure;

	nla_nest_end(skb, battr);

	if (reset) {
		atomic64_sub(n_packets, &band->stats.n_packets);
		atomic64_sub(n_bytes, &band->stats.n_bytes);
	}
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, battr);
	return -1;
}

static int nft_meter_do_dump(struct sk_buff *skb, struct nft_meter *priv,
			     bool reset)
{
	u64 n_packets, n_bytes;
	struct nlattr *battr;

	n_packets = atomic64_read(&priv->stats.n_packets);
	n_bytes = atomic64_read(&priv->stats.n_bytes);

	if (nla_put_be64(skb, NFTA_METER_BYTES, cpu_to_be64(n_bytes),
			 NFTA_COUNTER_PAD) ||
	    nla_put_be64(skb, NFTA_METER_PACKETS, cpu_to_be64(n_packets),
			 NFTA_COUNTER_PAD) ||
	    nla_put_be32(skb, NFTA_METER_FLAGS, cpu_to_be32(priv->flags)))
		goto nla_put_failure;

	if (priv->n_bands == 0)
		goto no_band;

	if (priv->n_bands == 1) {
		if (nft_meter_band_do_dump(skb, &priv->bands[0], reset))
			goto nla_put_failure;
	} else {
		int i;
		battr = nla_nest_start(skb, NFTA_METER_BANDS);
		if (!battr) {
			goto nla_put_failure;
		}
		for (i = 0; i < priv->n_bands; i++) {
			if (nft_meter_band_do_dump(skb, &priv->bands[i],
						   reset))
				goto nla_put_bands_failure;
		}
		nla_nest_end(skb, battr);
	}

no_band:
	if (reset) {
		atomic64_sub(n_packets, &priv->stats.n_packets);
		atomic64_sub(n_bytes, &priv->stats.n_bytes);
	}
	return 0;

nla_put_bands_failure:
	nla_nest_cancel(skb, battr);

nla_put_failure:
	return -1;
}

static void nft_meter_do_destroy(struct nft_meter *priv)
{
	kfree(priv->bands);
}

static void nft_meter_obj_eval(struct nft_object *obj,
			       struct nft_regs *regs,
			       const struct nft_pktinfo *pkt)
{
	struct nft_meter *priv = nft_obj_data(obj);

	nft_meter_do_eval(priv, regs, pkt);
}

static int nft_meter_obj_init(const struct nft_ctx *ctx,
			      const struct nlattr * const tb[],
			      struct nft_object *obj)
{
	struct nft_meter *priv = nft_obj_data(obj);

	return nft_meter_do_init(tb, priv);
}


static int nft_meter_obj_dump(struct sk_buff *skb, struct nft_object *obj,
			      bool reset)
{
	struct nft_meter *meter = nft_obj_data(obj);

	return nft_meter_do_dump(skb, meter, reset);
}

static void nft_meter_obj_destroy(struct nft_object *obj)
{
	struct nft_meter *priv = nft_obj_data(obj);

	nft_meter_do_destroy(priv);
}

static const struct nla_policy nft_meter_policy[NFTA_METER_MAX + 1] = {
	[NFTA_METER_PACKETS]	= { .type = NLA_U64 },
	[NFTA_METER_BYTES]	= { .type = NLA_U64 },
	[NFTA_METER_FLAGS]	= { .type = NLA_U32 },
	[NFTA_METER_BAND]	= { .type = NLA_NESTED },
	[NFTA_METER_BANDS]	= { .type = NLA_NESTED },
};

static struct nft_object_type nft_meter_obj __read_mostly = {
	.type		= NFT_OBJECT_METER,
	.size		= sizeof(struct nft_meter),
	.maxattr	= NFTA_METER_MAX,
	.policy		= nft_meter_policy,
	.eval		= nft_meter_obj_eval,
	.init		= nft_meter_obj_init,
	.destroy	= nft_meter_obj_destroy,
	.dump		= nft_meter_obj_dump,
	.owner		= THIS_MODULE,
};

static void nft_meter_eval(const struct nft_expr *expr,
			   struct nft_regs *regs,
			   const struct nft_pktinfo *pkt)
{
	struct nft_meter *priv = nft_expr_priv(expr);

	nft_meter_do_eval(priv, regs, pkt);
}

static int nft_meter_dump(struct sk_buff *skb, const struct nft_expr *expr)
{
	struct nft_meter *priv = nft_expr_priv(expr);

	return nft_meter_do_dump(skb, priv, false);
}

static int nft_meter_init(const struct nft_ctx *ctx,
			  const struct nft_expr *expr,
			  const struct nlattr * const tb[])
{
	struct nft_meter *priv = nft_expr_priv(expr);

	return nft_meter_do_init(tb, priv);
}

static void nft_meter_destroy(const struct nft_ctx *ctx,
			      const struct nft_expr *expr)
{
	struct nft_meter *priv = nft_expr_priv(expr);

	nft_meter_do_destroy(priv);
}

static struct nft_expr_type nft_meter_type;
static const struct nft_expr_ops nft_meter_ops = {
	.type		= &nft_meter_type,
	.size		= NFT_EXPR_SIZE(sizeof(struct nft_meter)),
	.eval		= nft_meter_eval,
	.init		= nft_meter_init,
	.destroy	= nft_meter_destroy,
	.dump		= nft_meter_dump,
};

static struct nft_expr_type nft_meter_type __read_mostly = {
	.name		= "meter",
	.ops		= &nft_meter_ops,
	.policy		= nft_meter_policy,
	.maxattr	= NFTA_METER_MAX,
	.flags		= NFT_EXPR_STATEFUL,
	.owner		= THIS_MODULE,
};

static int __init nft_meter_module_init(void)
{
	int err;

	err = nft_register_obj(&nft_meter_obj);
	if (err < 0)
		return err;

	err = nft_register_expr(&nft_meter_type);
	if (err < 0) {
		nft_unregister_obj(&nft_meter_obj);
		return err;
	}

	return 0;
}

static void __exit nft_meter_module_exit(void)
{
	nft_unregister_expr(&nft_meter_type);
	nft_unregister_obj(&nft_meter_obj);
}

module_init(nft_meter_module_init);
module_exit(nft_meter_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andy Zhou <azhou@ovn.org>");
MODULE_ALIAS_NFT_EXPR("meter");
MODULE_ALIAS_NFT_OBJ(NFT_OBJECT_METER);
