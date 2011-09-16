#include <linux/kernel.h>
#include <linux/ip.h>
#include <net/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/module.h>

#include "xt_ipaddr.h"

static bool ipaddr_mt4(const struct iphdr *iph,
		const struct xt_ipaddr_mtinfo *info)
{
	pr_info("SRC=%pI4 \n", &iph->saddr);
	pr_info("DST=%pI4 \n", &iph->daddr);

	if (info->flags & XT_IPADDR_SRC)
		if ((iph->saddr != info->src.ip) ^
				!!(info->flags & XT_IPADDR_SRC_INV)) {
			pr_notice("src IP - no match\n");
			return false;
		}

	if (info->flags & XT_IPADDR_DST)
		if ((iph->daddr != info->dst.ip) ^
				!!(info->flags & XT_IPADDR_DST_INV)) {
			pr_notice("dst IP - no match\n");
			return false;
		}

	return true;
}

static bool ipaddr_mt6(const struct ipv6hdr *iph,
		const struct xt_ipaddr_mtinfo *info)
{
	pr_info("SRC=%pI6 \n", &iph->saddr);
	pr_info("DST=%pI6 \n", &iph->daddr);

	if (info->flags & XT_IPADDR_SRC)
		if ((ipv6_addr_cmp(&iph->saddr, &info->src.in6) != 0) ^
				!!(info->flags & XT_IPADDR_SRC_INV))
			return false;
	if (info->flags & XT_IPADDR_DST)
		if ((ipv6_addr_cmp(&iph->daddr, &info->dst.in6) != 0) ^
				!!(info->flags & XT_IPADDR_DST_INV))
			return false;
	return true;
}

static bool ipaddr_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	if (par->family == NFPROTO_IPV4)
		return ipaddr_mt4(ip_hdr(skb), par->matchinfo);
	else if (par->family == NFPROTO_IPV6)
		return ipaddr_mt6(ipv6_hdr(skb), par->matchinfo);
	return false;
}

static int ipaddr_mt_check(const struct xt_mtchk_param *par)
{
	const struct xt_ipaddr_mtinfo *info = par->matchinfo;
	pr_info("Added a rule with -m ipaddr in the %s table; this rule is "
			"reachable through hooks 0x%x\n",
			par->table, par->hook_mask);
	if (!(info->flags & (XT_IPADDR_SRC | XT_IPADDR_DST))) {
		pr_info("not testing for anything\n");
		return -EINVAL;
	}
	if (ntohl(info->src.ip) == 0xDEADBEEF) {
		/* This just for fun */
		pr_info("I’m sorry, Dave. I’m afraid I can’t let you do that.\n");
		return -EPERM;
	}
	return 0;
}

static void ipaddr_mt_destroy(const struct xt_mtdtor_param *par)
{
	const struct xt_ipaddr_mtinfo *info = par->matchinfo;
	pr_info("Test for address %08lX removed\n", info->src.ip);
}

static struct xt_match ipaddr_mt_reg __read_mostly = {
	.name = "ipaddr",
	.revision = 0,
	.family = NFPROTO_UNSPEC,
	.match = ipaddr_mt,
	.checkentry = ipaddr_mt_check,
	.destroy = ipaddr_mt_destroy,
	.matchsize = sizeof(struct xt_ipaddr_mtinfo),
	.me = THIS_MODULE,
};


static int __init ipaddr_mt_init(void)
{
	int ret;
	ret = xt_register_match(&ipaddr_mt_reg);

	pr_info("The Netfilter module has been successfully loaded...\n");

	return 0;
}

static void __exit ipaddr_mt_exit(void)
{
	xt_unregister_match(&ipaddr_mt_reg);
	pr_info("The Netfilter module has been successfully unloaded...\n");
}

module_init(ipaddr_mt_init);
module_exit(ipaddr_mt_exit);

MODULE_AUTHOR("Juan Antonio Osorio <jaosorior@gmail.com>");
MODULE_DESCRIPTION("Xtables: Match source/destination address");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_ipaddr");
MODULE_ALIAS("ip6t_ipaddr");
