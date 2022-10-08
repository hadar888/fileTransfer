#ifndef PAYLOAD_H
#define PAYLOAD_H

#include<string>

class Payload {
public:
	virtual std::string payloadToJsonString() {
		return "payloadToJsonString base class\n";
	}
};

class RegisterPayload : public Payload {
public:
	char name[255];

	RegisterPayload(const char* name) {
		memcpy(this->name, name, sizeof(char) * 255);
	}

	RegisterPayload(Payload* payload) {

	}

	std::string payloadToJsonString() {
		std::string nameStr(this->name);

		return "\"{"
			"'Name': '" + nameStr + "'"
			"}\"";
	}
};

class RegisterOkPayload : public Payload {
public:
	unsigned char clientId[16];

	RegisterOkPayload(unsigned char* clientId) {
		memcpy(this->clientId, clientId, sizeof(char) * 16);
	}
};

class SendPublicKeyPayload : public Payload {
public:
	char name[255];
	std::string publicKey = { 0 };

	SendPublicKeyPayload(const char* name, const char* publicKey) {
		memcpy(this->name, name, sizeof(char) * 255);
		this->publicKey = publicKey;
	}

	SendPublicKeyPayload(Payload* payload) {

	}

	std::string payloadToJsonString() {
		std::string nameStr(this->name);

		return "\"{"
			"'Name': '" + nameStr + "', "
			"'Public Key': '" + this->publicKey + "'"
			"}\"";
	}
};

class GotAesEncreptedKeyPayload : public Payload {
public:
	unsigned char clientId[16];
	const char* encreptedKey;

	GotAesEncreptedKeyPayload(unsigned char clientId[16], std::string encreptedKey, int encreptedKeyLen) {
		memcpy(this->clientId, clientId, sizeof(char) * 16);
		this->encreptedKey = encreptedKey.c_str();
	}
};

#endif 