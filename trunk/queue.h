/*      $Id: $      */
/*      $OpenBSD: queue.h,v 1.32 2007/04/30 18:42:34 pedro Exp $        */
/*      $NetBSD: queue.h,v 1.11 1996/05/16 05:17:14 mycroft Exp $       */
/*
 * Copyright (c) 2008 Mark Heily <devel@heily.com>
 * Copyright (c) 1991, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)queue.h     8.5 (Berkeley) 8/20/94
 */

/*
 * Portability wrapper for <sys/queue.h> to provide modern features.
 *
 * The primary target is GNU libc which still uses a 4.4BSD-era 
 * header file. 
 */ 

#ifndef _QUEUE_H
#define _QUEUE_H

#include <sys/queue.h>

#ifndef LIST_FIRST
#define LIST_FIRST(head)                ((head)->lh_first)
#endif

#ifndef LIST_END
#define LIST_END(head)                  NULL
#endif

#ifndef LIST_EMPTY
#define LIST_EMPTY(head)                (LIST_FIRST(head) == LIST_END(head))
#endif

#ifndef LIST_NEXT
#define LIST_NEXT(elm, field)           ((elm)->field.le_next)
#endif

#ifndef LIST_FOREACH
#define LIST_FOREACH(var, head, field)                                  \
        for((var) = LIST_FIRST(head);                                   \
            (var)!= LIST_END(head);                                     \
            (var) = LIST_NEXT(var, field))

#endif

#endif /* _QUEUE_H */
