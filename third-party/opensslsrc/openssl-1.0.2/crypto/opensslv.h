#ifndef HEADER_OPENSSLV_H
# define HEADER_OPENSSLV_H

#ifdef  __cplusplus
extern "C" {
#endif

/*-
 * Numeric release version identifier:
 * MNNFFPPS: major minor fix patch status
 * The status nibble has one of the values 0 for development, 1 to e for betas
 * 1 to 14, and f for release.  The patch level is exactly that.
 * For example:
 * 0.9.3-dev      0x00903000
 * 0.9.3-beta1    0x00903001
 * 0.9.3-beta2-dev 0x00903002
 * 0.9.3-beta2    0x00903002 (same as ...beta2-dev)
 * 0.9.3          0x0090300f
 * 0.9.3a         0x0090301f
 * 0.9.4          0x0090400f
 * 1.2.3z         0x102031af
 *
 * For continuity reasons (because 0.9.5 is already out, and is coded
 * 0x00905100), between 0.9.5 and 0.9.6 the coding of the patch level
 * part is slightly different, by setting the highest bit.  This means
 * that 0.9.5a looks like this: 0x0090581f.  At 0.9.6, we can start
 * with 0x0090600S...
 *
 * (Prior to 0.9.3-dev a different scheme was used: 0.9.2b is 0x0922.)
 * (Prior to 0.9.5a beta1, a different scheme was used: MMNNFFRBB for
 *  major minor fix final patch/beta)
 */
/* facebook specific patches applied
 *
 *  fb01: @brianp  Reduce memory usage during handshaking
 *        @afrind  Allow asynchronous callbacks for session cache lookup
 *        @afrind  Further reduce memory usage during handshaking
 *        @afrind  Thread local md_rand implementation
 *        @afrind  EARLY_RELEASE_BBIO
 *        @ps      Use setbuffer for stdio in BIO routines
 *        @kafai   RSA private key async logic (bin compatibility in
 *                 SSL, SSL_CTX and RSA_METHOD struct)
 *        @kafai   RSA private key async logic (crypto/rsa)
 *        @kafai   RSA private key async logic (ssl)
 *        @saw     Support verification of TPM EK certificate chains with
 *                 mismatched serial numbers
 *  fb02: @mzlee   Support client-side cutthrough mode (i.e., false start)
 *  fb03: @avr     ECDSA asynchronous signatures during SSL (changes sizes of
 *                 structs SSL and SSL_CTX)
 *  fb04: @avr     Cloudflare Chacha20Poly patch (AVX2 support disabled)
 *  fb05: @mzlee   Add a FB patch number define. Patch number should match the
 *                 version text
 *  fb06: @avr     TLS cached info patch according to draft-23, see D3378025
 *  fb07: @pmehra  Add IPv6 support for openssl binary, see D3947458
 *  fb08: @avr     CF's new Chacha20 patch for 1.0.2j; removed old patches
 *  fb09: @subodh  Remove SSL3_FLAGS_DELAY_CLIENT_FINISHED in cutthrough mode
 */
# define OPENSSL_VERSION_NUMBER  0x100020bfL
# define OPENSSL_FB_PATCH_NUMBER 0x09L
# ifdef OPENSSL_FIPS
#  define OPENSSL_VERSION_TEXT    "OpenSSL 1.0.2k-fips-fb09  26 Jan 2017"
# else
#  define OPENSSL_VERSION_TEXT    "OpenSSL 1.0.2k-fb09  26 Jan 2017"
# endif
# define OPENSSL_VERSION_PTEXT   " part of " OPENSSL_VERSION_TEXT

/*-
 * The macros below are to be used for shared library (.so, .dll, ...)
 * versioning.  That kind of versioning works a bit differently between
 * operating systems.  The most usual scheme is to set a major and a minor
 * number, and have the runtime loader check that the major number is equal
 * to what it was at application link time, while the minor number has to
 * be greater or equal to what it was at application link time.  With this
 * scheme, the version number is usually part of the file name, like this:
 *
 *      libcrypto.so.0.9
 *
 * Some unixen also make a softlink with the major verson number only:
 *
 *      libcrypto.so.0
 *
 * On Tru64 and IRIX 6.x it works a little bit differently.  There, the
 * shared library version is stored in the file, and is actually a series
 * of versions, separated by colons.  The rightmost version present in the
 * library when linking an application is stored in the application to be
 * matched at run time.  When the application is run, a check is done to
 * see if the library version stored in the application matches any of the
 * versions in the version string of the library itself.
 * This version string can be constructed in any way, depending on what
 * kind of matching is desired.  However, to implement the same scheme as
 * the one used in the other unixen, all compatible versions, from lowest
 * to highest, should be part of the string.  Consecutive builds would
 * give the following versions strings:
 *
 *      3.0
 *      3.0:3.1
 *      3.0:3.1:3.2
 *      4.0
 *      4.0:4.1
 *
 * Notice how version 4 is completely incompatible with version, and
 * therefore give the breach you can see.
 *
 * There may be other schemes as well that I haven't yet discovered.
 *
 * So, here's the way it works here: first of all, the library version
 * number doesn't need at all to match the overall OpenSSL version.
 * However, it's nice and more understandable if it actually does.
 * The current library version is stored in the macro SHLIB_VERSION_NUMBER,
 * which is just a piece of text in the format "M.m.e" (Major, minor, edit).
 * For the sake of Tru64, IRIX, and any other OS that behaves in similar ways,
 * we need to keep a history of version numbers, which is done in the
 * macro SHLIB_VERSION_HISTORY.  The numbers are separated by colons and
 * should only keep the versions that are binary compatible with the current.
 */
# define SHLIB_VERSION_HISTORY ""
# define SHLIB_VERSION_NUMBER "1.0.2"


#ifdef  __cplusplus
}
#endif
#endif                          /* HEADER_OPENSSLV_H */
