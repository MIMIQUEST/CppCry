#include <openssl/evp.h>
#include <openssl/aes.h>
#include <string>
#include <iostream>

int main() {
  // 你好
  std::string plaintext = "nihao";

  // キと初期ベクトルの
  unsigned char key[32];
  unsigned char iv[16];
  RAND_bytes(key, sizeof(key));
  RAND_bytes(iv, sizeof(iv));

  // 暗号文バッファ
  unsigned char ciphertext[plaintext.size() + AES_BLOCK_SIZE];
  int ciphertext_len = 0;

  // 暗号化
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len,
                    (const unsigned char*)plaintext.c_str(), plaintext.size());
  int final_len = 0;
  EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
  ciphertext_len += final_len;
  EVP_CIPHER_CTX_free(ctx);

  // 暗号文を出力
  std::cout << "Ciphertext: ";
  for (int i = 0; i < ciphertext_len; i++) {
    std::cout << std::hex << (int)ciphertext[i];
  }
  std::cout << std::endl;

  return 0;
}
