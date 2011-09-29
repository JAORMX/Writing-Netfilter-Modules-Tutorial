#include <xtables.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "xt_ipaddr.h"
#include "libxt_ipaddr.h"


static const struct option ipaddr_mt_opts[] = {
	{.name = "ipsrc", .has_arg = true, .val = '1'},
	{.name = "ipdst", .has_arg = true, .val = '2'},
	{NULL},
};

static struct xtables_match ipaddr_mt4_reg = {
	.version = XTABLES_VERSION,
	.name = "ipaddr",
	.revision = 0,
	.family = NFPROTO_IPV4,
	.size = XT_ALIGN(sizeof(struct xt_ipaddr_mtinfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_ipaddr_mtinfo)),
	.help = ipaddr_mt_help,
	.init = ipaddr_mt4_init,
	.parse = ipaddr_mt4_parse,
	.final_check = ipaddr_mt_check,
	.print = ipaddr_mt4_print,
	.save = ipaddr_mt4_save,
	.extra_opts = ipaddr_mt_opts,
};

static struct xtables_match ipaddr_mt6_reg = {
	.version = XTABLES_VERSION,
	.name = "ipaddr",
	.revision = 0,
	.family = NFPROTO_IPV6,
	.size = XT_ALIGN(sizeof(struct xt_ipaddr_mtinfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_ipaddr_mtinfo)),
	.help = ipaddr_mt_help,
	.init = ipaddr_mt6_init,
	.parse = ipaddr_mt6_parse,
	.final_check = ipaddr_mt_check,
	.print = ipaddr_mt6_print,
	.save = ipaddr_mt6_save,
	.extra_opts = ipaddr_mt_opts,
};


static void ipaddr_mt4_init(struct xt_entry_match *match)
{
	struct xt_ipaddr_mtinfo *info = (void *)match->data;
	inet_pton(PF_INET, "127.0.0.1", &info->dst.in);
}

static void ipaddr_mt6_init(struct xt_entry_match *match)
{
	struct xt_ipaddr_mtinfo *info = (void *)match->data;
	inet_pton(PF_INET6, "::1", &info->dst.in);
}

/*
 * Prints the rule.
 */
static void ipaddr_mt4_save(const void *entry, const struct xt_entry_match *match)
{
	const struct xt_ipaddr_mtinfo *info = (const void *)match->data;

	if (info ->flags & XT_IPADDR_SRC) {
		if (info->flags & XT_IPADDR_SRC_INV)
			printf("! ");

		printf("--ipsrc %s ", xtables_ipaddr_to_numeric(&info->src.in));
	}

	if (info->flags & XT_IPADDR_DST) {
		if (info->flags & XT_IPADDR_DST_INV)
			printf("! ");

		printf("--ipdst %s ",
				xtables_ipaddr_to_numeric(&info->dst.in));
	}
}

/*
 * Prints the rule.
 */
static void ipaddr_mt6_save(const void *entry, const struct xt_entry_match *match)
{
	const struct xt_ipaddr_mtinfo *info = (const void *)match->data;

	if (info ->flags & XT_IPADDR_SRC) {
		if (info->flags & XT_IPADDR_SRC_INV)
			printf("! ");

		printf("--ipsrc %s ", xtables_ip6addr_to_numeric(&info->src.in6));
	}

	if (info->flags & XT_IPADDR_DST) {
		if (info->flags & XT_IPADDR_DST_INV)
			printf("! ");

		printf("--ipdst %s ",
				xtables_ip6addr_to_numeric(&info->dst.in6));
	}
}


static void ipaddr_mt4_print(const void *entry,
		const struct xt_entry_match *match, int numeric)
{
	const struct xt_ipaddr_mtinfo *info = (const void *)match->data;

	if (info->flags & XT_IPADDR_SRC) {
		printf("src IP ");

		if (info->flags & XT_IPADDR_SRC_INV)
			printf("! ");

		if (numeric)
			printf("%s ", numeric ?
					xtables_ipaddr_to_numeric(&info->src.in) :
					xtables_ipaddr_to_anyname(&info->src.in));
	}

	if (info->flags & XT_IPADDR_DST) {
		printf("dst IP ");

		if (info->flags & XT_IPADDR_DST_INV)
			printf("! ");

		printf("%s ", numeric ?
				xtables_ipaddr_to_numeric(&info->dst.in):
				xtables_ipaddr_to_anyname(&info->dst.in));
	}
}


static void ipaddr_mt6_print(const void *entry,
		const struct xt_entry_match *match, int numeric)
{
	const struct xt_ipaddr_mtinfo *info = (const void *)match->data;

	if (info->flags & XT_IPADDR_SRC) {
		printf("src IP ");

		if (info->flags & XT_IPADDR_SRC_INV)
			printf("! ");

		if (numeric)
			printf("%s ", numeric ?
					xtables_ip6addr_to_numeric(&info->src.in6) :
					xtables_ip6addr_to_anyname(&info->src.in6));
	}

	if (info->flags & XT_IPADDR_DST) {
		printf("dst IP ");

		if (info->flags & XT_IPADDR_DST_INV)
			printf("! ");

		printf("%s ", numeric ?
				xtables_ip6addr_to_numeric(&info->dst.in6):
				xtables_ip6addr_to_anyname(&info->dst.in6));
	}
}

static int ipaddr_mt4_parse(int c, char **argv, int invert,
		unsigned int *flags, const void *entry,
		struct xt_entry_match **match)
{
	struct xt_ipaddr_mtinfo *info = (void *)(*match)->data;
	struct in_addr *addrs, mask;
	unsigned int naddrs;
	char str[INET_ADDRSTRLEN];

	switch (c) {
		case '1': /* --ipsrc */
			if (*flags & XT_IPADDR_SRC)
				xtables_error(PARAMETER_PROBLEM, "xt_ipaddr: "
						"Only use \"--ipsrc\" once!");

			*flags |= XT_IPADDR_SRC;
			info->flags |= XT_IPADDR_SRC;

			if (invert)
				info->flags |= XT_IPADDR_SRC_INV;

			xtables_ipparse_any(optarg, &addrs, &mask, &naddrs);
			inet_ntop(AF_INET, &mask, str, INET_ADDRSTRLEN);
			printf("OZZ => MASK = %s\n", str);

			if (naddrs != 1)
				xtables_error(PARAMETER_PROBLEM,
						"%s does not resolves to exactly "
						"one address", optarg);

			/* Copy the single address */
			memcpy(&info->src.in, addrs, sizeof(*addrs));
			return true;

		case '2': /* --ipdst */
			if (*flags & XT_IPADDR_DST)
				xtables_error(PARAMETER_PROBLEM, "xt_ipaddr: "
						"Only use \"--ipdst\" once!");

			*flags |= XT_IPADDR_DST;
			info->flags |= XT_IPADDR_DST;

			if (invert)
				info->flags |= XT_IPADDR_DST_INV;

			// addrs = xtables_numeric_to_ipaddr(optarg, &info->dst.in);
			addrs = &info->dst.in;

			if (addrs == NULL)
				xtables_error(PARAMETER_PROBLEM,
						"Parse error at %s\n", optarg);

			memcpy(&info->dst.in, addrs, sizeof(*addrs));
			return true;
	}
	return false;
}

static int ipaddr_mt6_parse(int c, char **argv, int invert,
		unsigned int *flags, const void *entry,
		struct xt_entry_match **match)
{
	struct xt_ipaddr_mtinfo *info = (void *)(*match)->data;
	struct in6_addr *addrs, mask;
	unsigned int naddrs;
	char str[INET6_ADDRSTRLEN];

	switch(c) {
		case '1': /* --ipsrc */
			if (*flags & XT_IPADDR_SRC)
				xtables_error(PARAMETER_PROBLEM, "xt_ipaddr: "
						"Only use \"--ipsrc\" once!");

			*flags |= XT_IPADDR_SRC;
			info->flags |= XT_IPADDR_SRC;

			if (invert)
				info->flags |= XT_IPADDR_SRC_INV;

			//addrs = xtables_numeric_to_ip6addr(optarg);
			xtables_ip6parse_any(optarg, &addrs, &mask, &naddrs);
			inet_ntop(AF_INET6, &mask, str, INET6_ADDRSTRLEN);
			printf("OZZ => MASK = %s\n", str);


			if(addrs == NULL)
				xtables_error(PARAMETER_PROBLEM, "xt_ipaddr: " 
					"Parse error at %s", optarg);

			memcpy(&info->src.in6, addrs, sizeof(*addrs));

			return true;
		case '2': /* --ipdst */
			if (*flags & XT_IPADDR_DST)
				xtables_error(PARAMETER_PROBLEM, "xt_ipaddr: "
						"Only use \"--ipdst\" once!");

			*flags |= XT_IPADDR_DST;
			info->flags |= XT_IPADDR_DST;

			if (invert)
				info->flags |= XT_IPADDR_DST_INV;

			// addrs = xtables_numeric_to_ipaddr(optarg, &info->dst.in);
			addrs = xtables_numeric_to_ip6addr(optarg);

			if (addrs == NULL)
				xtables_error(PARAMETER_PROBLEM,
						"Parse error at %s\n", optarg);

			memcpy(&info->dst.in, addrs, sizeof(*addrs));
			return true;
	}

	return false;
}

static void ipaddr_mt_check(unsigned int flags)
{
	if (flags == 0)
		xtables_error(PARAMETER_PROBLEM, "xt_ipaddr: You need to "
				"specify at least \"--ipsrc\" or \"--ipdst\".");
}


static void ipaddr_mt_help(void)
{
	printf(
			"ipaddr match options:\n"
			"[!] --ipsrc addr Match source address of packet\n"
			"[!] --ipdst addr Match destination address of packet\n"
		  );
}


void _init(void)
{
	xtables_register_match(&ipaddr_mt4_reg);
	xtables_register_match(&ipaddr_mt6_reg);
}

