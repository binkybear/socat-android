/* source xio-hex.h */
/* Copyright Gerhard Rieger */
/* Published under the GNU General Public License V.2, see file COPYING */

/* copied from xio-test.h and adapted */

#ifndef __xio_hex_h_included
#define __xio_hex_h_included 1

extern const union xioaddr_desc *xioaddrs_hex[];

extern size_t xioread_hex(struct single *sfd, void *buff, size_t bufsiz);
extern size_t xiowrite_hex(struct single *sfd, const void *buff, size_t bytes);

#endif /* !defined(__xio_hex_h_included) */
