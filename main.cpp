#include "DataBase.hpp"
#include "Cloud.hpp"
#include "Response.hpp"
#include "CryptoManager.hpp"

int main() {



    try {

    DataBase dataBase;
    Cloud cloud1, cloud2, cloud3, cloud4;
    Response response1, response2;
    CryptoManager cryptoManager;
    u_short port;
    std::string name, host, filePathStr;
    dataBase.extractTransferInfo(host, port, name, filePathStr);

    std::filesystem::path filePath(filePathStr);

    std::vector<uint8_t> cID, publicKey, privateKey, privateKey1;


    //Checks if the file of user data exists, and registers if not
    if (!dataBase.userExist()) {
        //Register User
        response1 = cloud1.registerName(name);
        cID = response1.getClientID();

        cryptoManager.initRSAKeys();
        publicKey = cryptoManager.getPublicKey();
        privateKey = cryptoManager.getPrivateKey();
        privateKey1 = cryptoManager.getPrivateKey();

        response2 = cloud1.sendPublicKey(name, cID, publicKey); //@@@@@@@@@@@

        //Storing User details
        dataBase.writeUserDetailsToFile(name, cID, privateKey);

        dataBase.savePrivateKey(privateKey1);
        return 5;
    }
    else {
        std::string tName;
        dataBase.extractUserDetails(tName, cID, privateKey);
        dataBase.loadPrivateKey(privateKey1);
        cryptoManager.initRSAKeys(privateKey1);
        response2 = cloud2.login(name, cID);
    }

    std::vector<uint8_t> encryptedAesKey = response2.getEncryptedSymmetricKey();

    cryptoManager.initAESKey(encryptedAesKey);    
    Response response4 = cloud1.sendFile(cID, filePath, cryptoManager);
    }
    catch (std::exception e) {
        std::cerr << e.what();
    }

    return 0;

}