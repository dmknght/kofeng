/*
 * ksb_args.c - The usage text and the options every mode takes (toolchain and
 *    paths).
 */

#include "ksb.h"

/* Consumes the options this tool takes wherever they appear, and leaves
 * the rest of argv in place for the caller to read positionally. */
int ksb_opt_take(struct ksb_ctx *ksb, int *argc, char **argv)
{
	const struct { const char *name; const char **at; } s_str[] = {
		{ "--cc",       &ksb->opt.cc       },
		{ "--ld",       &ksb->opt.ld       },
		{ "--include",  &ksb->opt.include  },
		{ "--ldscript", &ksb->opt.ldscript },
		{ "--basedir",  &ksb->opt.basedir  },
		{ "--triple",   &ksb->opt.triple   },
		{ "--tmpdir",   &ksb->opt.tmpdir   }
	};
	int i = 1, w = 1, n = *argc;

	for (; i < n; i++) {
		size_t k;
		int hit = 0;

		if (strcmp(argv[i], "--keep-work") == 0) {
			ksb->opt.keep_work = 1;
			continue;
		}
		for (k = 0; k < sizeof s_str / sizeof s_str[0]; k++)
			if (strcmp(argv[i], s_str[k].name) == 0) {
				if (i + 1 >= n) {
					fprintf(stderr, "ksigbuilder: %s needs"
						" a value\n", argv[i]);
					return 0;
				}
				*s_str[k].at = argv[++i];
				hit = 1;
				break;
			}
		if (!hit)
			argv[w++] = argv[i];
	}
	argv[w] = NULL;
	*argc = w;
	return 1;
}

/*
 * EVERY MODE, ONE LINE EACH.
 *
 * It listed two of the seven - the default and --extract - so a reader looking
 * for --tree or --module, which is how this is actually driven, was told the
 * tool had no such thing. Short is the goal; short and incomplete is a
 * different failure from long and unreadable, and this had that one.
 */
void ksb_usage(const char *argv0)
{
	fprintf(stderr,
		"ksigbuilder - compile signature sources into a database\n"
		"\n"
		"  %s --tree <bases-dir> <artefact-dir> <out-dir>\n"
		"                    the whole source tree, in one step\n"
		"  %s --module <src.c> <artefact-dir>\n"
		"                    one source to its artefacts\n"
		"  %s <artefact-dir> <out-dir>\n"
		"                    artefacts to packs\n"
		"\n"
		"  --build           build identification\n"
		"  --image <linked.elf> <out.blob>    a linked module to a blob\n"
		"  --object <obj.o> <out.blob>        the same, unlinked\n"
		"  --extract <signature.c> <out.pat.h> <out.names> <out.pre> <out.strs>\n"
		"                    the declarations out of one source;\n"
		"                    what --module calls\n"
		"  --arch-mask <names>      a KOF_ARCH mask from names\n"
		"  --subtype-mask <names>   a KOF_SUBTYPE mask from names\n",
		argv0, argv0, argv0);
}
