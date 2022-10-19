#ifndef PAYLOAD_H
#define PAYLOAD_H

#include<string>

class Payload {
public:
	virtual void payloadToJsonString(char* payloadDataToSend) {
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

	void payloadToJsonString(char* payloadDataToSend) {
		std::memcpy(&payloadDataToSend[0], &this->name, sizeof(char) * 255);
	}
};

class RegisterOkPayload : public Payload {
public:
	unsigned char clientId[16];
	RegisterOkPayload(){}

	RegisterOkPayload(unsigned char* clientId) {
		memcpy(this->clientId, clientId, sizeof(char) * 16);
	}
};

class SendPublicKeyPayload : public Payload {
public:
	char name[255] = { 0 };
	char publicKey[160] = { 0 };

	SendPublicKeyPayload(const char* name, const char* publicKey) {
		memcpy(this->name, name, sizeof(char) * 255);
		memcpy(this->publicKey, publicKey, sizeof(char) * 160);
	}

	SendPublicKeyPayload(Payload* payload) {

	}

	void payloadToJsonString(char* payloadDataToSend) {
		std::memcpy(&payloadDataToSend[0], &this->name, sizeof(char) * 255);
		std::memcpy(&payloadDataToSend[255], &this->publicKey, sizeof(char) * 160);
	}
};

class GotAesEncreptedKeyPayload : public Payload {
public:
	unsigned char clientId[16] = { 0 };
	char encreptedKey[128] = { 0 }; // TODO: shuold not be 128

	GotAesEncreptedKeyPayload() {

	}

	GotAesEncreptedKeyPayload(unsigned char clientId[16], char* encreptedKey, int encreptedKeyLen) {
		memcpy(this->clientId, clientId, sizeof(char) * 16);
		memcpy(this->encreptedKey, encreptedKey, sizeof(char) * encreptedKeyLen);
	}
};

class SendFilePayload : public Payload {
public:
	char clientId[16];
	int contentSize;
	char fileName[255];
	char* msgContent;

	SendFilePayload() {

	}

	SendFilePayload(char clientId[16], int contentSize, char fileName[255], const char* msgContent) {
		memcpy(this->clientId, clientId, sizeof(char) * 16);
		this->contentSize = contentSize;
		memcpy(this->fileName, fileName, sizeof(char) * 255);
		this->msgContent = (char*)calloc(contentSize, sizeof(char));
		memcpy(this->msgContent, msgContent, sizeof(char) * contentSize);
	}

	~SendFilePayload() {
		free(msgContent);
	}


	void payloadToJsonString(char* payloadDataToSend) {
		std::memcpy(&payloadDataToSend[0], &this->clientId, sizeof(char) * 16);
		std::memcpy(&payloadDataToSend[16], &this->contentSize, sizeof(int));
		std::memcpy(&payloadDataToSend[20], &this->fileName, sizeof(char) * 255);
		std::memcpy(&payloadDataToSend[275], this->msgContent, sizeof(char) * 255);
	}
};

class GotFilePayload : public Payload {
public:
	unsigned char clientId[16];
	unsigned int contentSize;
	unsigned char fileName[255];
	unsigned int cksum;

	GotFilePayload() {

	}

	GotFilePayload(unsigned char clientId[16], unsigned int contentSize, unsigned char fileName[255], unsigned int cksum) {
		memcpy(this->clientId, clientId, sizeof(char) * 16);
		memcpy(&this->contentSize, &contentSize, sizeof(int));
		memcpy(this->fileName, fileName, sizeof(char) * 255);
		memcpy(&this->cksum, &cksum, sizeof(int));
	}
};

class CrcMsgPayload : public Payload {
public:
	char clientId[16];
	char fileName[255];

	CrcMsgPayload() {

	}

	CrcMsgPayload(char clientId[16], char fileName[255]) {
		memcpy(this->clientId, clientId, sizeof(char) * 16);
		memcpy(this->fileName, fileName, sizeof(char) * 255);
	}

	void payloadToJsonString(char* payloadDataToSend) {
		std::memcpy(&payloadDataToSend[0], &this->clientId, sizeof(char) * 16);
		std::memcpy(&payloadDataToSend[16], &this->fileName, sizeof(char) * 255);
	}
};

#endif 