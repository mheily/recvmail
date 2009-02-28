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


/*
 * test_file_exists(path)
 *
 * Test if a file exists at a given <path>
 *
 * Returns: 1 if the file exists, 0 if it does not, or -1 if there was a system error
 *
 */
int file_exists(const char *path)
{
	struct stat st;
	
	if (stat(path, &st) < 0) {
		if ( errno != ENOENT ) {
			log_errno("stat(2)");
			return -1;
		}
		return 0;
	} else {
		return 1;
	}
}


/*
 * valid_pathname(pathname)
 *
 * Test if <pathname> contains unwanted characters or is otherwise illegal.
 *
 * Returns: 0 if pathname is legal, or -1 if it is illegal.
 *
 */
int valid_pathname(const char *pathname)
{
	static const char *ftext = "0123456789abcdefghijklmnopqrstuvwxyz./ABCDEFGHIKJLMNOPQRSTUVWXYZ-_";
	size_t	len;
	int i;

	assert (pathname);

	/* Validate inputs */
	len = strlen(pathname);
	if (len == 0 || len > PATH_MAX)
		return -EINVAL;

	/* Check each character */
	for (i = 0; i < len; i++) {
                if ( strchr(ftext, pathname[i]) == NULL ) {
                                log_warning("invalid pathname: illegal characters");
				return -EINVAL;
                }
        }

	return 0;
}

