/*		$Id: $		*/

/*
 * Copyright (c) 2004-2007 Mark Heily <devel@heily.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "recvmail.h"

#define DOMAIN_MAX		63
#define HOSTNAME_MAX		63

/*
 * domain_exists(chroot_fd, domain)
 *
 * Checks if <domain> exists in the mailstore located at <chroot_fd>
 *
 * Returns: 1 if the mailbox exists, 0 if it does not, or -1 if there was a system error
 *
 */
int
domain_exists(int chroot_fd, const char *domain)
{
	struct stat st;
	char *path = NULL;
	int result;

	if ( valid_domain(domain) < 0)
		return -EINVAL;

	if (asprintf(&path, "store/%s", domain) < 0)
		return -ENOMEM;

	result = fstatat(chroot_fd, path, &st, 0);
	free(path);

        if (result < 0 && errno != ENOENT)
                log_errno("fstatat(2)");

	log_debug("domain %s checked; result %d", domain, result);

        return (result == 0 ? 1 : 0);
}


/*
 * valid_domain(domain)
 *
 * Checks <domain> for validity.
 *
 * Returns: 0 if domain is valid, -1 if invalid
 *
 */
int valid_domain(const char *domain)
{
	int i;
	size_t len;
	static const char *dtext = "abcdefghijklmnopqrstuvwxyz.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

	/* Check the length */
	len = strlen(domain);
	if (len == 0 || len > DOMAIN_MAX)
		return -EINVAL;

	/* Disallow leading dots */
	if (domain[0] == '.')
		return -EINVAL;

	/* Check for illegal characters */
	for (i = 0; i < len; i++) {
		if ( strchr(dtext, domain[i]) == NULL ) {
			return -EINVAL;
		}
	}

	return 0;
}


/*
 * valid_address(address)
 *
 * Check if <address> is a syntactically valid RFC-2821 e-mail address
 *
 * Returns: 0 if address is valid, -1 if it is invalid
 *
 */
int valid_address(const struct rfc2822_addr *addr)
{
	static const char *atext = "abcdefghijklmnopqrstuvwxyz.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?^_~";
	int 	i;
	size_t	len;

	assert(addr);

	/* Sanitize variables */
	if (valid_domain(addr->domain) < 0)
		return -EINVAL;
	len = strlen(addr->user);
	if (len == 0 || len > USERNAME_MAX || addr->user[0] == '.')
		return -EINVAL;

	/* Check for illegal characters */
	for (i = 0; i < len; i++) {
		if ( !strchr(atext, addr->user[i]) ) 
			return -EINVAL;
	}

	return 0;
}


struct rfc2822_addr * 
rfc2822_addr_new()
{
	return calloc(1, sizeof(struct rfc2822_addr));
}

/**
 * Parse an Internet mail address.
 *
 * Takes an RFC2822 email address (<foo@bar.com>) and validates it, returning
 * the canonical address or NULL if invalid.
 *
 * Returns: 0 if success, -1 if error
 *
 */
int
rfc2822_addr_parse(struct rfc2822_addr * dest, const char *src) 
{
	char user[64];
	char domain[64];
	char	*p;
	int 	i;

	/* Ignore the SIZE parameter*/
	if ((p = strstr(src, " SIZE=")))
		memset(p, 0, 1);

	/* Replace '<' and '>' with whitespace */
	if ((p = strchr(src, '<')) != NULL)
		memset(p, ' ', 1);
	if ((p = strchr(src, '>')) != NULL)
		memset(p, ' ', 1);

	/* Split the string into two parts */
	i = sscanf(src, " %63[a-zA-Z0-9_.+=%#?~^-]@%63[a-zA-Z0-9_.-] ", 
				(char *) &user, (char *) &domain);
	if (i < 2 || i == EOF) {
		log_warning("%s", "unable to parse address");
		return -EINVAL;
	}
	//log_debug("parsed %s as [%s], [%s]", src, dest->user, dest->domain);

	/* Copy the buffers to the caller */
	if ((dest->user = strdup((char *) &user)) == NULL)
		return -ENOMEM;
	if ((dest->domain = strdup((char *) &domain)) == NULL) {
		free(dest->user);
		return -ENOMEM;
	}

	/* Compute the path to the mailbox */
	if (asprintf(&dest->path, "store/%s/%s", dest->domain, dest->user) < 0) {
		free(dest->user);
		free(dest->domain);
		return -ENOMEM;
	}

	return 0;
}


void
rfc2822_addr_free(struct rfc2822_addr * addr)
{
	free(addr->user);
	free(addr->domain);
	free(addr->path);
	free(addr);
}
