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
	std::string value;
        const std::string key3 = "92e9bf1aad214c69b1f3a18a03aae8dc";
        if (ANDROID) { // 4.23
	    const std::string key1 = "949b7649dac84a00aa8144b05bfb1bee";
	    const std::string key2 = "d458b26b985802d71bd884342fb773e6";
	    const std::string key4 = "b7592a92bdb12b22073d7bd5ed7edaf0";
            value = key1 + version + key2 + std::to_string(hash) + key3 + std::to_string(protocol) + rid + key4;
        } else { // 4.24
	    const std::string key1 = "42e2ae20305244ddaf9b0de5e897fc74";
	    const std::string key2 = "ccc18d2e2ca84e0a81ba29a0af2edc9c";
	    const std::string key4 = "58b92130c89c496b96164b776d956242";
            value = version + key1 + std::to_string(protocol) + key2 + std::to_string(hash) + key3 + rid + key4;
	}

	return MD5(value);
}
