#ifndef HEADER_H
#define HEADER_H

#include <string>

class Header {
public:
	char version;
	short code;
	int payloadSize;

	Header(){}
	
	Header(char version, short code, int payloadSize) {
		this->code = code;
		this->payloadSize = payloadSize;
		this->version = version;
	}

	std::string headerToJsonString() {
		return "\"{"
			"'Version': " + std::to_string(this->version) + ", "
			"'Code': " + std::to_string(this->code) + ", "
			"'Payload size': " + std::to_string(this->payloadSize) +
			"}\"";
	}
};

class ClientHeader: public Header {
public:
	char clientId[16];

	ClientHeader(char clientId[16], char version, short code, int payloadSize) {
		std::memcpy(this->clientId, clientId, sizeof(this->clientId));
		this->code = code;
		this->payloadSize = payloadSize;
		this->version = version;
	}

	void headerToJsonString(char* headerDataToSend) {
		std::memcpy(&headerDataToSend[0], &this->clientId, sizeof(char) * 16);
		std::memcpy(&headerDataToSend[16], &this->version, sizeof(char));
		std::memcpy(&headerDataToSend[17], &this->code, sizeof(short));
		std::memcpy(&headerDataToSend[19], &this->payloadSize, sizeof(int));
	}
};

#endif