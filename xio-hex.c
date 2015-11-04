/* source: xio-hex.c */
/* Copyright Gerhard Rieger */
/* Published under the GNU General Public License V.2, see file COPYING */

/* this file contains the source for an intermediate address that converts
   binary stream to hex and vice versa */
/* copied from xio-test.c and adapted */

#include "xiosysincludes.h"
#include "xioopen.h"

#include "xio-hex.h"


#if WITH_HEX	/* enable or disable the HEX addresses at build/compile time */

/* the headers of the init functions, one for each variant: */
/*  bidirectional (forward and reverse) */
static int xioopen_hex(int argc, const char *argv[], struct opt *opts,
				  int xioflags, xiofile_t *xxfd,
				  unsigned groups, int dummy1, int dummy2,
				  int dummy3);

/* the address descriptor records, again bi, forward, reverse */
static const struct xioaddr_inter_desc xiointer_hex0ro = { XIOADDR_PROT, "hex", 0, XIOBIT_RDONLY, 0/*groups*/, XIOSHUT_UNSPEC, XIOCLOSE_UNSPEC, xioopen_hex, 0, 0, 0, XIOBIT_WRONLY HELP("") };
static const struct xioaddr_inter_desc xiointer_hex0wo = { XIOADDR_PROT, "hex", 0, XIOBIT_WRONLY, 0/*groups*/, XIOSHUT_UNSPEC, XIOCLOSE_UNSPEC, xioopen_hex, 0, 0, 0, XIOBIT_RDONLY HELP("") };
static const struct xioaddr_inter_desc xiointer_hex0rw = { XIOADDR_PROT, "hex", 0, XIOBIT_RDWR,   0/*groups*/, XIOSHUT_UNSPEC, XIOCLOSE_UNSPEC, xioopen_hex, 0, 0, 0, XIOBIT_RDWR   HELP("") };

/* the set of the available HEX address descriptor records. When the HEX keyword is used these records are looked up for a variant matching bi-/unidrectional and number of args */
const union xioaddr_desc *xioaddrs_hex[] = {
   (union xioaddr_desc *)&xiointer_hex0ro,
   (union xioaddr_desc *)&xiointer_hex0wo,
   (union xioaddr_desc *)&xiointer_hex0rw,
   NULL };


/* this is the init function */
/* it will be called by socat with the following parameter: */
static int xioopen_hex(
	int argc,		/* number of keyword and args given in address */
	const char *argv[],	/* array of string pointers of args */
	struct opt *opts,	/* a pointer to the provided addr options */
	int xioflags,		/* some flags regarding directions e.a. */
	xiofile_t *xxfd,	/* the extended file descriptor record, to be filled */
	unsigned groups,	/* !!! why? */
	int dummy,		/* parameter 1 from address descriptor record */
	int dummy2,		/* parameter 2 from address descriptor record */
	int dummy3		/* parameter 3 from address descriptor record */
		       ) {
   struct single *xfd = &xxfd->stream;	/* select the component from the C union */
   int result;

   assert(argc == 1);	/* only the keyword; number must match due to address descriptor */
   assert(!(xfd->rfd < 0 && xfd->wfd < 0));	/* at least one valid direction */

   applyopts(-1, opts, PH_INIT);	/* apply/eval address options in phase PH_INIT */
   if (applyopts_single(xfd, opts, PH_INIT) < 0)  return -1;
   /* here initialize the xfd.para.hex if you have one  */
   xfd->dtype = XIODATA_HEX;

   Notice("opening HEX");
   /* perform action for opening, eg wait for incoming connection or
      perform initial dialog */
   applyopts(xfd->rfd, opts, PH_ALL);
   if ((result = _xio_openlate(xfd, opts)) < 0)
      return result;
   return 0;
}


/* this function is invoked by socat when a block/paket of binary data is to be converted to hex and transferred "down the pipe"
   Paramters: the extended file descriptor, the buffer containing the data, and the amount of data
   This function performs the necessary conversions (might need to provide an outbut buffer!), writes the data to the appropriate system file descriptor synchronously, and possibly performs cleanup.
   Afterwards it returns the number of bytes successfully forwarded, or -1 (and errno) if an error occurred. */
size_t xiowrite_hex(struct single *sfd, const void *buff, size_t bytes) {
   int fd = sfd->wfd;
   uint8_t *obuff;
   ssize_t writt;
   size_t i, j;
   int _errno;

   /* allocate space */
   if ((obuff = Malloc(2*bytes)) == NULL) {
      return -1;
   }

   /* convert data */
   i=0; j=0; while (i<bytes) {
      int c;
      c=(((uint8_t *)buff)[i++]);
      switch (c>>4) {
      case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 9: obuff[j++]='0'+(c>>4); break;
      default: obuff[j++]='a'+((c>>4)-10); break;
      }	
      switch (c&0x0f) {
      case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8: case 9: obuff[j++]='0'+(c&0x0f); break;
      default: obuff[j++]='a'+((c&0x0f)-10); break;
      }	
   }
   
   /* write the data, overcome soft errors */
   /* try to write the data in one piece to keep packet boundaries */
   do {
      writt = Write(fd, obuff, 2*bytes);
   } while (writt < 0 && errno == EINTR);
   /* perform error handling */
   if (writt < 0) {
      _errno = errno;
      switch (_errno) {
      case EPIPE:
      case ECONNRESET:
	 if (sfd->cool_write) {
	    Notice4("write(%d, %p, "F_Zu"): %s",
		    fd, obuff, 2*bytes, strerror(_errno));
	    break;
	 }
	 /*PASSTHROUGH*/
      default:
	 Error4("write(%d, %p, "F_Zu"): %s",
		fd, obuff, 2*bytes, strerror(_errno));
      }
      errno = _errno;
      free(obuff);
      return -1;
   }
   if ((size_t)writt < bytes) {
      Warn2("write() only wrote "F_Zu" of "F_Zu" bytes",
	    writt, 2*bytes);
   }
   /* cleanup */
   /* you may avoid alloc/free on each packet by saving the pointer in the xfd.para.hex area, if you define it. */
   free(obuff);
   return writt;
}

/* this function is invoked by socat when (hex) data is available on the file descriptor coming upwards from the pipeblock/paket and is to be converted to binary.
   Paramters: the extended file descriptor, the return buffer where the binary data be written to, and the length of the buffer or maximal amount of binary data to be provided.
   This function reads the hex (protocol) data from the file descripor, performs the necessary conversions (might need to provide an outbut buffer!), performs cleanup, and returns the binary data. It reads at most so many characters from the file descriptor that the converted data fits in the return buffer. 
   it returns the number of bytes extracted, or -1 (and errno) if an error occurred. Returning 0 means EOF; when 0 bytes are generated but not EOF, set errno to EAGAIN and return -1.
*/
size_t xioread_hex(struct single *sfd, void *buff, size_t bufsiz) {
   int fd = sfd->rfd;
   ssize_t bytes;
   int _errno;
   uint8_t *ibuff;
   size_t i, j; 
   char c1, c2;

   /* allocate space */
   if ((ibuff = Malloc(2*bufsiz)) == NULL) {
      return -1;
   }

   /* read data */
   do {
      bytes = Read(fd, ibuff, bufsiz);
   } while (bytes < 0 && errno == EINTR);
   /* perform error handling */
   if (bytes < 0) {
      _errno = errno;
      switch (_errno) {
      case EPIPE: case ECONNRESET:
	 Warn4("read(%d, %p, "F_Zu"): %s",
	       fd, buff, bufsiz, strerror(_errno));
	 break;
      default:
	 Error4("read(%d, %p, "F_Zu"): %s",
		fd, buff, bufsiz, strerror(_errno));
      }
      return -1;
   }
   
   if (bytes == 0) {
      return 0;
   }

   /* convert data */
   i=0; j=0; while (i<bytes) {
      unsigned int y;
      if (sfd->para.hex.single) {
	 c1 = sfd->para.hex.single;
	 sfd->para.hex.single = 0;
      } else {
	 c1 = ibuff[i++];
	 while (i<=bytes && !isxdigit(c1))  c1 = ibuff[i++];
	 if (i>bytes) {
	    break;
	 }
      }
      c2 = ibuff[i++];
      while (i<=bytes && !isxdigit(c2))  c2 = ibuff[i++];
      if (!isxdigit(c2)) {
	 sfd->para.hex.single = c1;
	 break;
      }
      /* now we have two chars available for conversion */
      if (isdigit(c1)) y = (c1-'0') << 4;
      if (isalpha(c1)) y = (toupper(c1)-'A'+10) << 4;
      if (isdigit(c2)) y |= c2-'0';
      if (isalpha(c2)) y |= (toupper(c2)-'A'+10);

      ((uint8_t *)buff)[j++] = y;
   }

   if (j == 0) {
      errno = EAGAIN; return -1;
   }
      
   return j;
}

#endif /* WITH_HEX */

