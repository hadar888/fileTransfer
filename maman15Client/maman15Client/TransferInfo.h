#ifndef TRANSFER_H
#define TRANSFER_H

#include <string>
#include <fstream>

class TransferInfo {
public:
	std::string serverIp;
	std::string serverPort;
	std::string name;
	std::string fileToSendName;

	TransferInfo() {
		std::ifstream transferFile("transfer.info");
		if (transferFile.is_open()) {
			getline(transferFile, this->serverIp, ':');
			getline(transferFile, this->serverPort);
			getline(transferFile, this->name);
			getline(transferFile, this->fileToSendName);
		}
	}
};

#endif