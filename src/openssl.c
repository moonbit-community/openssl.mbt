#include "../vendor/include/openssl/ssl.h"
#include <moonbit.h>
#include <string.h>

MOONBIT_FFI_EXPORT
int32_t
moonbit_OPENSSL_init_ssl(uint64_t opts) {
  return OPENSSL_init_ssl(opts, NULL);
}

MOONBIT_FFI_EXPORT
const SSL_METHOD *
moonbit_TLS_client_method(void) {
  return TLS_client_method();
}

MOONBIT_FFI_EXPORT
SSL_CTX *
moonbit_SSL_CTX_new(const SSL_METHOD *method) {
  return SSL_CTX_new(method);
}

MOONBIT_FFI_EXPORT
void
moonbit_SSL_CTX_set_cert_store(SSL_CTX *ctx, X509_STORE *store) {
  return SSL_CTX_set_cert_store(ctx, store);
}

MOONBIT_FFI_EXPORT
void
moonbit_SSL_CTX_free(SSL_CTX *ctx) {
  return SSL_CTX_free(ctx);
}

MOONBIT_FFI_EXPORT
SSL *
moonbit_SSL_new(SSL_CTX *ctx) {
  return SSL_new(ctx);
}

MOONBIT_FFI_EXPORT
void
moonbit_SSL_free(SSL *ssl) {
  return SSL_free(ssl);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_set_fd(SSL *ssl, int fd) {
  return SSL_set_fd(ssl, fd);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_SSL_connect(SSL *ssl) {
  return SSL_connect(ssl);
}

MOONBIT_FFI_EXPORT
int
moonbit_SSL_read(SSL *ssl, void *buf, int num) {
  return SSL_read(ssl, buf, num);
}

MOONBIT_FFI_EXPORT
int
moonbit_SSL_write(SSL *ssl, const void *buf, int num) {
  return SSL_write(ssl, buf, num);
}

MOONBIT_FFI_EXPORT
int
moonbit_SSL_shutdown(SSL *ssl) {
  return SSL_shutdown(ssl);
}

MOONBIT_FFI_EXPORT
int
moonbit_SSL_get_error(const SSL *ssl, int ret_code) {
  return SSL_get_error(ssl, ret_code);
}

MOONBIT_FFI_EXPORT
X509_STORE *
moonbit_X509_STORE_new(void) {
  return X509_STORE_new();
}

MOONBIT_FFI_EXPORT
void
moonbit_X509_STORE_free(X509_STORE *store) {
  return X509_STORE_free(store);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_X509_STORE_add_cert(X509_STORE *store, X509 *x509) {
  return X509_STORE_add_cert(store, x509);
}

MOONBIT_FFI_EXPORT
X509 *
moonbit_X509_new(void) {
  return X509_new();
}

MOONBIT_FFI_EXPORT
void
moonbit_X509_free(X509 *x509) {
  return X509_free(x509);
}

MOONBIT_FFI_EXPORT
BIO *
moonbit_BIO_new_mem_buf(const void *buf, int len) {
  return BIO_new_mem_buf(buf, len);
}

MOONBIT_FFI_EXPORT
int32_t
moonbit_BIO_free(BIO *bio) {
  return BIO_free(bio);
}

MOONBIT_FFI_EXPORT
X509 *
moonbit_PEM_read_bio_X509(BIO *bp) {
  return PEM_read_bio_X509(bp, NULL, NULL, NULL);
}
