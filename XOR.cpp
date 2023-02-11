#include <iostream>
#include <string>

std::string xor_encrypt(const std::string &plaintext, const std::string &key) {
  std::string ciphertext(plaintext.size(), ' ');

  for (int i = 0; i < plaintext.size(); i++) {
    ciphertext[i] = plaintext[i] ^ key[i % key.size()];
  }

  return ciphertext;
}

int main() {
  // 平文
  std::string plaintext = "nihao";

  // キ
  std::string key = "key";

  // 暗号
  std::string ciphertext = xor_encrypt(plaintext, key);

  // 出力
  std::cout << "Ciphertext: " << ciphertext << std::endl;

  return 0;
}
