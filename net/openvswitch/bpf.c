/* Copyright (c) 2015 Nicira Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/err.h>
#include <linux/bpf.h>
#include <linux/openvswitch.h>
#include <linux/skbuff.h>

static u64 bpf_helper_output(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct sk_buff *skb = (struct sk_buff *) (unsigned long) r1;
	uint32_t port = (uint32_t) (unsigned long) r2;

	printk("helper output %p to port %d\n", skb, port);
	return 0;
}

struct bpf_func_proto bpf_helper_output_proto = {
	.func = bpf_helper_output,
	.gpl_only = true,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_ANYTHING,  /* XXX from context */
	.arg2_type = ARG_ANYTHING,
	.arg3_type = ARG_ANYTHING,
	.arg4_type = ARG_ANYTHING,
};

#define BPF_CONTEXT_ACCESS(CTXT, FIELD, RW) \
	[offsetof(struct CTXT, FIELD)] = { \
		FIELD_SIZEOF(struct CTXT, FIELD), \
		RW  \
	}

static const struct bpf_func_proto *ovs_func_proto(int func_id)
{
	switch (func_id) {
	case OVS_BPF_FUNC_output:
		return &bpf_helper_output_proto;
	default:
		return NULL;
	}
}

static const struct bpf_context_access {
	int size;
	enum bpf_access_type type;
} bpf_ctx_access[] = {
	BPF_CONTEXT_ACCESS(ovs_bpf_action_ctxt, skb, BPF_READ),
	BPF_CONTEXT_ACCESS(ovs_bpf_action_ctxt, arg0, BPF_READ),
	BPF_CONTEXT_ACCESS(ovs_bpf_action_ctxt, arg1, BPF_READ)
};

static bool test_is_valid_access(int off, int size, enum bpf_access_type type)
{
	const struct bpf_context_access *access;

	if (off < 0 || off >= ARRAY_SIZE(bpf_ctx_access))
		return false;

	access = &bpf_ctx_access[off];
	if (access->size == size && (access->type & type))
		return true;

	return false;
}

static struct bpf_verifier_ops ovs_bpf_ops = {
	.get_func_proto = ovs_func_proto,
	.is_valid_access = test_is_valid_access,
};

static struct bpf_prog_type_list tl_prog = {
	.ops = &ovs_bpf_ops,
	.type = BPF_PROG_TYPE_OPENVSWITCH,
};

static int __init register_ovs_bpf_ops(void)
{
	bpf_register_prog_type(&tl_prog);
	return 0;
}
late_initcall(register_ovs_bpf_ops);
