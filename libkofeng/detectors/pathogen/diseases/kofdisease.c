#include "kofdisease.h"

#include <string.h>

const char *kof_disease_check(const char *s)
{
	size_t l = strlen(s);
	const char *c;

	if (!l)
		return "a disease is not empty";
	if (l > KOF_DIAG_DISEASE_LEN)
		return "a disease is at most 63 characters";
	for (c = s; *c; c++)
		if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') ||
		      *c == '-' || *c == '_' || *c == '/'))
			return "a disease is lower-case letters, digits, - _ and /";
	if (s[0] == '/' || s[l - 1u] == '/' || strstr(s, "//"))
		return "a disease is layer/behaviour, not a path with an empty part";
	return NULL;
}
