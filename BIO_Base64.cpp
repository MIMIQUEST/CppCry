#include <iostream>
#include <string>
#include <vector>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

std::string base64_encode(const unsigned char *input, int length) {
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  std::string result(bptr->data, bptr->length);
  BIO_free_all(b64);

  return result;
}

int main() {
  // 平文
  std::string plaintext = "";

  // 暗号文
  std::string ciphertext = base64_encode((const unsigned char*)plaintext.c_str(), plaintext.size());

  // 暗号文の出力
  std::cout << "Ciphertext: " << ciphertext << std::endl;

  return 0;
}
