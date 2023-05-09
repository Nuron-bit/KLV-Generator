#define _CRT_SECURE_NO_WARNINGS
#include <string>
#include <algorithm>
#include <openssl/evp.h>

const int PROTOCOL = 189;
const std::string GAME_VERSION = "4.23";
const bool ANDROID = false;

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
	const static std::string keys[] = {
        "13c93f386db9da3e00dda16d770b0c83",
        "6b1c01f9128a62a2c97b1a0da4612168",
        "3402d278d8519a522c94d122e98e2e49",
        "ba95613bc0fd94a9d89c5919670e7d5d"
   	};
	
	return MD5(version + keys[0] + std::to_string(protocol) + keys[1] + std::to_string(hash) + keys[2] + rid + keys[3]);
}
