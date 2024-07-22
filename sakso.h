#pragma once
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>
#include <iostream>
#include <iomanip>
#include <Windows.h>
#include <iphlpapi.h>
#include <ctime>
#include <sstream>

#include "sdk/cheats.h"
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "IPHLPAPI.lib")

std::string getComputerUUID() {
    std::string uuid;

    // wmic komutunu çaðýr ve çýktýsýný oku
    FILE* pipe = _popen("wmic csproduct get uuid", "r");
    if (!pipe) {
        std::cerr << "wmic komutu baþlatýlamadý!" << std::endl;
        return "";
    }

    char cikti[128];
    int lin = 0;
    while (fgets(cikti, sizeof(cikti), pipe) != NULL) {
        if (lin++ == 1) { // Ýlk satýrý atla, ikinci satýrý al
            uuid = cikti;
            break;
        }
    }

    _pclose(pipe);

    // Gereksiz karakterleri temizle
    size_t pos = uuid.find_first_of("\r\n");
    if (pos != std::string::npos) {
        uuid.erase(pos);
    }

    return uuid;

}

// Verilen string'i SHA-512 ile hashle
std::string SHA512Hash(const std::string& input) {
    HCRYPTPROV hCryptProv;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "";
    }

    HCRYPTHASH hHash;
    if (!CryptCreateHash(hCryptProv, CALG_SHA_512, 0, 0, &hHash)) {
        CryptReleaseContext(hCryptProv, 0);
        return "";
    }

    if (!CryptHashData(hHash, reinterpret_cast<const BYTE*>(input.c_str()), input.length(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return "";
    }

    DWORD hashSize = 0;
    DWORD dwDataLen = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashSize), &dwDataLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return "";
    }

    BYTE* hashValue = new BYTE[hashSize];
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashValue, &hashSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        delete[] hashValue;
        return "";
    }

    std::stringstream ss;
    for (DWORD i = 0; i < hashSize; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hashValue[i]);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
    delete[] hashValue;

    return ss.str();
}
void SaveKeyToRegistry(const std::string& key) {
    HKEY hKey;
    LONG result = RegCreateKeyEx(HKEY_CURRENT_USER, L"Software\\Exela", 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);

    if (result == ERROR_SUCCESS) {
        result = RegSetValueEx(hKey, L"UserKey", 0, REG_SZ, (const BYTE*)key.c_str(), key.length() + 1);

        if (result == ERROR_SUCCESS) {
            std::cout << "User key saved to Registry." << std::endl;
        }
        else {
            std::cerr << "Failed to save user key to Registry." << std::endl;
        }

        RegCloseKey(hKey);
    }
    else {
        std::cerr << "Failed to create or open Registry key." << std::endl;
    }
}
int calc() {
    double tanjant = tan(19 * (M_PI / 180)); // 8 derecenin tanjantý
    double cosinus = cos(12 * (M_PI / 180)); // 9 derecenin kosinüsü

    double sonuc = (tanjant * 12 * cosinus * 2222) * 15; // Ýþlem sonucu

    return sonuc;
}

std::string loginning() {
    int qwqwq = calc();
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << qwqwq; // std::fixed ve std::setprecision kullanarak virgülden sonrasýný al
    return ss.str();
}

int calc2() {
    double tanjant = tan(19 * (M_PI / 180)); // 8 derecenin tanjantý
    double cosinus = cos(12 * (M_PI / 180)); // 9 derecenin kosinüsü

    double sonuc = (tanjant * 12 * cosinus * 2222) * 110; // Ýþlem sonucu
    double sonuc2 = (sonuc + 1992 + 1992 + 9999);
    return sonuc2;
}

std::string loginning2() {
    int qwqwq = calc2();
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << qwqwq; // std::fixed ve std::setprecision kullanarak virgülden sonrasýný al
    return ss.str();
}


void cheat()
{
    if (userInput == "")
    {
        exit(0);
    }

    if (lexemvemem::lexemvefind_driver()) {
        system("cls");
    }
    else {
        system("cls");
        system("color c");
        for (char& c : notfounddrver) {
            std::cout << c;
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Her karakterin arasýnda 50 milisaniye bekleyin
        }
        Sleep(3000);
        exit(0);
    }

    if (lexemvemem::lexemvefind_process(L"VALORANT-Win64-Shipping.exe")) {
        if (userInput == "")
        {
            exit(0);
        }
        lexemvevirtualaddy = get_guarded_reg();
        check1::guard = lexemvevirtualaddy;
        base = lexemvemem::lexemvefind_image();
        system("cls");
        for (char& c : activecheat) {
            std::cout << c;
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Her karakterin arasýnda 50 milisaniye bekleyin
        }


        LAGMMEEE::LASTRTC();
    }
    else {
        system("cls");
        system("color c");
        for (char& c : ntfoundgame) {
            std::cout << c;
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Her karakterin arasýnda 50 milisaniye bekleyin
        }
        Sleep(2000);
        exit(0);
    }
}

// Veritabanýndaki end_date deðerini kontrol et
void checkEndDate(sql::Connection* con, const std::string& userInput) {
    try {
        // SQL sorgusunu hazýrla
        sql::PreparedStatement* pstmt;
        pstmt = con->prepareStatement("SELECT `subscribeend` FROM `keys` WHERE `key` = ?");
        pstmt->setString(1, userInput);

        // Sorguyu çalýþtýr
        sql::ResultSet* res = pstmt->executeQuery();

        // Sonuçlarý kontrol et
        if (res->next()) {
            std::string endDateStr = res->getString("subscribeend");

            // Veritabanýndaki tarih ve saat formatýný çözümle
            std::tm endDate = {};
            std::istringstream ss(endDateStr);
            ss >> std::get_time(&endDate, "%Y.%m.%d:%H:%M");

            if (ss.fail()) {
                std::cerr << "Tarih çözümleme hatasý!" << std::endl;
                // Hata durumunda gerekli iþlemleri yapabilirsin.
            }

            // Þu anki tarihi ve saati al
            std::time_t currentTime = std::time(nullptr);
            std::tm* currentTM = std::localtime(&currentTime);

            // Tarihi karþýlaþtýr
            if (std::mktime(&endDate) > std::mktime(currentTM)) {
                // Geçerli tarih, kullanýcý süresi devam ediyor
                std::cout << "You have successfully logged in." << std::endl;
            }
            else {
                // Kullanýcýnýn süresi bitmiþ
                std::cout << "Your subscription has expired." << std::endl;
                Sleep(3000);
                exit(0);
            }
        }

        // Kaynaklarý temizle
        delete res;
        delete pstmt;
    }
    catch (sql::SQLException& e) {
        std::cout << "MySQL baðlantý hatasý: " << e.what() << std::endl;
    }
}

void dwerwet() {

    sql::mysql::MySQL_Driver* driver;
    sql::Connection* con;
    std::string user1 = loginning2();
    std::string user2 = loginning();
    int baba = 89;
    int baba1 = 116;
    int baba3 = 27;
    int baba4 = 231;

    // MySQL veritabanýna baðlanmak için gerekli bilgiler
    std::string host = std::to_string(baba) + "." + std::to_string(baba1) + "." + std::to_string(baba3) + "." + std::to_string(baba4);
    std::string user = "MemoryLeakTracker";
    std::string password = user1 + user2 + "!";

    std::string database = "AppConfigStore";

    //std::cout << password;
    try {
        driver = sql::mysql::get_mysql_driver_instance();
        // Veritabanýna baðlan
        con = driver->connect(host, user, password);
        // Kullanýlacak veritabanýný seç
        con->setSchema(database);
        // SQL sorgusunu hazýrla
        sql::PreparedStatement* pstmt1;
        pstmt1 = con->prepareStatement("SELECT serverstatus FROM server");

        // Sorguyu çalýþtýr
        sql::ResultSet* res1 = pstmt1->executeQuery();

        // Sonuçlarý kontrol et
        if (res1->next()) {
            // Server status deðerini al
            int serverStatus = res1->getInt("serverstatus");

            // Server status kontrolü
            if (serverStatus == 1) {
                // Programýn normal devam etmesi için gerekli iþlemleri buraya ekleyin.
            }
            else {
                std::cout << "Server has issues. Closing the program." << std::endl;
                // Programý kapatmak için uygun bir iþlem yapabilirsiniz.
                exit(0);
            }
        }
        else {
            std::cout << "Error: Could not retrieve server status." << std::endl;
            // Programý kapatmak veya baþka bir iþlem yapmak istediðiniz durumu buraya ekleyin.
            exit(0);
        }
        // Sonuçlarý kontrol et


        //std::cout << getComputerUUID();

        std::cout << "Please enter your key: ";
        std::cin >> userInput;

        // SQL sorgusunu hazýrla
        sql::PreparedStatement* pstmt;
        pstmt = con->prepareStatement("SELECT * FROM `keys` WHERE `key` = ?");
        pstmt->setString(1, userInput);

        // Sorguyu çalýþtýr
        sql::ResultSet* res = pstmt->executeQuery();

        // Sonuçlarý kontrol et
        if (res->next()) {
            // Banned deðeri kontrol et
            string banned = res->getString("status");
            if (banned == "banned") {
                // Kullanýcý banlý, bilgilendir ve programý kapat
                std::cout << "You are banned. Please contact support for further assistance." << std::endl;
                Sleep(3000);
                exit(0);
            }

            // HWID deðeri boþ mu kontrol et
            std::string hwid = res->getString("hwid");
            if (hwid.empty()) {

                pstmt = con->prepareStatement("UPDATE `keys` SET `status` = 'activated' WHERE `key` = ?");
                pstmt->setString(1, userInput);
                pstmt->executeUpdate();
                // HWID deðeri boþsa, bilgisayarýn UUID deðerini al ve SHA-512 ile hashle
                std::string computerUUID = getComputerUUID();
                std::string hashedUUID = SHA512Hash(computerUUID);

                // SQL sorgusunu hazýrla
                pstmt = con->prepareStatement("UPDATE `keys` SET `hwid` = ? WHERE `key` = ?");
                pstmt->setString(1, hashedUUID);
                pstmt->setString(2, userInput);

                // Sorguyu çalýþtýr
                pstmt->executeUpdate();

                std::cout << "" << std::endl;
            }
            else {
                // HWID deðeri dolu ise, bilgisayarýn UUID deðerini al, SHA-512 ile hashle ve veritabanýndaki ile karþýlaþtýr
                std::string computerUUID = getComputerUUID();
                std::string hashedUUID = SHA512Hash(computerUUID);

                if (hwid == hashedUUID) {
                    // Kullanýcý banlý deðil ve HWID doðru, kontrol etEndDate fonksiyonunu çalýþtýr
                    checkEndDate(con, userInput);
                }
                else {
                    std::cout << "User could not be verified." << std::endl;
                    Sleep(3000);
                    exit(0);
                }
            }
        }
        else {
            std::cout << "Key value is incorrect." << std::endl;
            Sleep(3000);
            exit(0);
        }

        // Kaynaklarý temizle
        delete res;
        delete pstmt;
        delete con;

    }
    catch (sql::SQLException& e) {
        std::cerr << "didnt connect for mysql: " << e.what() << std::endl;
        Sleep(2500);
        exit(0);
    }
}
