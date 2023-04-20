#define _CRT_SECURE_NO_WARNINGS
#include <string>
#include <algorithm>
#include <openssl/evp.h>

const int PROTOCOL = 189;
const std::string GAME_VERSION = "4.23";

std::string MD5(const std::string& input) {
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len;
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
	EVP_DigestUpdate(ctx, input.c_str(), input.length());
	EVP_DigestFinal_ex(ctx, digest, &digest_len);
	EVP_MD_CTX_free(ctx);

	char md5string[33];
	for (int i = 0; i < 16; i++) {
		sprintf(&md5string[i * 2], "%02x", (unsigned int)digest[i]);
	}
	md5string[32] = '\0';

	std::string hash = std::string(md5string);
	std::transform(hash.begin(), hash.end(), hash.begin(), ::toupper);
	return hash;
}

std::string GenerateKLV(const int protocol, const int hash, const std::string& version, const std::string& rid) {
	const std::string key1 = "0b02ea1d8610bab98fbc1d574e5156f3";
	const std::string key2 = "b414b94c3279a2099bd817ba3a025cfc";
	const std::string key3 = "bf102589b28a8cc3017cba9aec1306f5";
	const std::string key4 = "dded9b27d5ce7f8c8ceb1c9ba25f378d";
	const std::string value = key1 + version + key2 + std::to_string(hash) + key3 + rid + key4 + std::to_string(protocol);

	return MD5(value);
}
