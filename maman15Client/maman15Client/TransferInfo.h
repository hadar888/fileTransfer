#ifndef TRANSFER_H
#define TRANSFER_H

#include <string>
#include <fstream>

class TransferInfo {
public:
	std::string serverIp;
	std::string serverPort;
	char name[255] = { 0 };
	std::string fileToSendName;

	TransferInfo() {
		std::ifstream transferFile("transfer.info");
		std::string nameString;

		if (transferFile.is_open()) {
			getline(transferFile, this->serverIp, ':');
			getline(transferFile, this->serverPort);
			getline(transferFile, nameString);
			memcpy(this->name, nameString.c_str(), nameString.size());
			getline(transferFile, this->fileToSendName);
		}
	}
};

#endif