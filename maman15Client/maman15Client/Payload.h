#ifndef PAYLOAD_H
#define PAYLOAD_H

#define PUBLIC_KEY_LENGTH 160

#include<string>

using namespace std;

class Payload {
public:
	virtual void payloadToBuffer(char* payloadDataToSend) {
	}
};

class RegisterPayload : public Payload {
public:
	char name[NAME_LENGTH];

	RegisterPayload(const char* name) {
		memcpy(this->name, name, sizeof(char) * NAME_LENGTH);
	}

	RegisterPayload(Payload* payload) {

	}

	void payloadToBuffer(char* payloadDataToSend) {
		memcpy(&payloadDataToSend[0], &this->name, sizeof(char) * NAME_LENGTH);
	}
};

class RegisterOkPayload : public Payload {
public:
	unsigned char clientId[UUID_LENGTH];
	RegisterOkPayload(){}

	RegisterOkPayload(unsigned char* clientId) {
		memcpy(this->clientId, clientId, sizeof(char) * UUID_LENGTH);
	}
};

class SendPublicKeyPayload : public Payload {
public:
	char name[NAME_LENGTH] = { 0 };
	char publicKey[PUBLIC_KEY_LENGTH] = { 0 };

	SendPublicKeyPayload(const char* name, const char* publicKey) {
		memcpy(this->name, name, sizeof(char) * NAME_LENGTH);
		memcpy(this->publicKey, publicKey, sizeof(char) * PUBLIC_KEY_LENGTH);
	}

	SendPublicKeyPayload(Payload* payload) {

	}

	void payloadToBuffer(char* payloadDataToSend) {
		memcpy(&payloadDataToSend[0], &this->name, sizeof(char) * NAME_LENGTH);
		memcpy(&payloadDataToSend[NAME_LENGTH], &this->publicKey, sizeof(char) * PUBLIC_KEY_LENGTH);
	}
};

class GotAesEncreptedKeyPayload : public Payload {
public:
	unsigned char clientId[UUID_LENGTH] = { 0 };
	char encreptedKey[128] = { 0 }; // TODO: shuold not be 128

	GotAesEncreptedKeyPayload() {

	}

	GotAesEncreptedKeyPayload(unsigned char clientId[UUID_LENGTH], char* encreptedKey, int encreptedKeyLen) {
		memcpy(this->clientId, clientId, sizeof(char) * UUID_LENGTH);
		memcpy(this->encreptedKey, encreptedKey, sizeof(char) * encreptedKeyLen);
	}
};

class SendFilePayload : public Payload {
public:
	unsigned char clientId[UUID_LENGTH];
	unsigned int contentSize;
	unsigned char fileName[FILE_PATH_LENGTH];
	char* msgContent;

	SendFilePayload() {

	}

	SendFilePayload(unsigned char clientId[UUID_LENGTH], int contentSize, char fileName[FILE_PATH_LENGTH], const char* msgContent) {
		memcpy(this->clientId, clientId, sizeof(char) * UUID_LENGTH);
		this->contentSize = contentSize;
		memcpy(this->fileName, fileName, sizeof(char) * FILE_PATH_LENGTH);
		this->msgContent = (char*)calloc(contentSize, sizeof(char));
		memcpy(this->msgContent, msgContent, sizeof(char) * contentSize);
	}

	~SendFilePayload() {
		free(msgContent);
	}


	void payloadToBuffer(char* payloadDataToSend) {
		memcpy(&payloadDataToSend[0], &this->clientId, sizeof(char) * UUID_LENGTH);
		memcpy(&payloadDataToSend[UUID_LENGTH], &this->contentSize, sizeof(int));
		memcpy(&payloadDataToSend[20], &this->fileName, sizeof(char) * FILE_PATH_LENGTH);
		memcpy(&payloadDataToSend[275], this->msgContent, sizeof(char) * this->contentSize);
	}
};

class GotFilePayload : public Payload {
public:
	unsigned char clientId[UUID_LENGTH];
	unsigned int contentSize;
	unsigned char fileName[FILE_PATH_LENGTH];
	unsigned int cksum;

	GotFilePayload() {

	}

	GotFilePayload(unsigned char clientId[UUID_LENGTH], unsigned int contentSize, unsigned char fileName[FILE_PATH_LENGTH], unsigned int cksum) {
		memcpy(this->clientId, clientId, sizeof(char) * UUID_LENGTH);
		memcpy(&this->contentSize, &contentSize, sizeof(int));
		memcpy(this->fileName, fileName, sizeof(char) * FILE_PATH_LENGTH);
		memcpy(&this->cksum, &cksum, sizeof(int));
	}
};

class CrcMsgPayload : public Payload {
public:
	unsigned char clientId[UUID_LENGTH];
	char fileName[FILE_PATH_LENGTH];

	CrcMsgPayload() {

	}

	CrcMsgPayload(unsigned char clientId[UUID_LENGTH], char fileName[FILE_PATH_LENGTH]) {
		memcpy(this->clientId, clientId, sizeof(char) * UUID_LENGTH);
		memcpy(this->fileName, fileName, sizeof(char) * FILE_PATH_LENGTH);
	}

	void payloadToBuffer(char* payloadDataToSend) {
		memcpy(&payloadDataToSend[0], &this->clientId, sizeof(char) * UUID_LENGTH);
		memcpy(&payloadDataToSend[UUID_LENGTH], &this->fileName, sizeof(char) * FILE_PATH_LENGTH);
	}
};

#endif 