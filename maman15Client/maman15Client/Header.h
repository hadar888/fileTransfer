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

	std::string headerToJsonString() {
		std::string clientIdStr(this->clientId);

		return "\"{"
			"'Client ID': '" + clientIdStr + "', "
			"'Version': " + std::to_string(this->version) + ", "
			"'Code': " + std::to_string(this->code) + ", "
			"'Payload size': " + std::to_string(this->payloadSize) +
			"}\"";
	}
};

#endif