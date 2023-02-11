#include <iostream>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main() {
    // キーのペアを生成します
    RSA *key_pair = RSA_generate_key(2048, RSA_F4, NULL, NULL);
　
  　// 公開鍵を取り出す
    RSA *public_key = RSAPublicKey_dup(key_pair);

    // 秘密鍵を取り出す
    RSA *private_key = RSAPrivateKey_dup(key_pair);

    // 平文はココ
    std::string plaintext = "nihao";
    int plaintext_len = plaintext.size();

    // 平文を暗号化する
    unsigned char *ciphertext = (unsigned char*)malloc(RSA_size(public_key));
    int ciphertext_len = RSA_public_encrypt(plaintext_len, (const unsigned char*)plaintext.c_str(),
                                             ciphertext, public_key, RSA_PKCS1_OAEP_PADDING);

    // 暗号文を復号
    unsigned char *decrypted = (unsigned char*)malloc(RSA_size(private_key));
    int decrypted_len = RSA_private_decrypt(ciphertext_len, ciphertext, decrypted,
                                            private_key, RSA_PKCS1_OAEP_PADDING);

    // 一致しますか
    std::string decrypted_str((char*)decrypted, decrypted_len);
    std::cout << (decrypted_str == plaintext ? "Y" : "N") << std::endl;

    // 確保したメモリを解放する
    RSA_free(key_pair);
    RSA_free(public_key);
    RSA_free(private_key);
    free(ciphertext);
    free(decrypted);

    return 0;
}
