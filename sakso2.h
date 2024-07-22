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
#include <ctime> // Bu k�t�phaneyi eklemeyi unutma
#include "sakso.h"
#include <sstream>
#pragma comment(lib, "IPHLPAPI.lib")
// HWID (UUID) ve Ekran Kart� Modelini Al


void cheatss()
{
    sql::mysql::MySQL_Driver* driver;
    sql::Connection* con;
    int baba = 89;
    int baba1 = 116;
    int baba3 = 27;
    int baba4 = 231;

    // MySQL veritaban�na ba�lanmak i�in gerekli bilgiler
    std::string user1 = loginning2();
    std::string user2 = loginning();
    std::string host = std::to_string(baba) + "." + std::to_string(baba1) + "." + std::to_string(baba3) + "." + std::to_string(baba4);

    // MySQL veritaban�na ba�lanmak i�in gerekli bilgiler
    std::string user = "MemoryLeakTracker";
    std::string password = user1 + user2 + "!";
    std::string database = "AppConfigStore";

    try {
        driver = sql::mysql::get_mysql_driver_instance();

        // Veritaban�na ba�lan
        con = driver->connect(host, user, password);

        // Kullan�lacak veritaban�n� se�
        con->setSchema(database);
        sql::PreparedStatement* pstmt1;
        pstmt1 = con->prepareStatement("SELECT serverstatus FROM server");

        // Sorguyu �al��t�r
        sql::ResultSet* res1 = pstmt1->executeQuery();

        // Sonu�lar� kontrol et
        if (res1->next()) {
            // Server status de�erini al
            int serverStatus = res1->getInt("serverstatus");

            // Server status kontrol�
            if (serverStatus == 1) {
                // Program�n normal devam etmesi i�in gerekli i�lemleri buraya ekleyin.
            }
            else {
                std::cout << "Server has issues. Closing the program." << std::endl;
                // Program� kapatmak i�in uygun bir i�lem yapabilirsiniz.
                exit(0);
            }
        }
        else {
            std::cout << "Error: Could not retrieve server status." << std::endl;
            // Program� kapatmak veya ba�ka bir i�lem yapmak istedi�iniz durumu buraya ekleyin.
            exit(0);
        }

    sql::PreparedStatement* pstmt;
    pstmt = con->prepareStatement("SELECT * FROM `keys` WHERE `key` = ?");
    pstmt->setString(1, userInput);

    // Sorguyu �al��t�r
    sql::ResultSet* res = pstmt->executeQuery();
    if (userInput.empty())	
    {
        BlueScreen();

    }
    if (userInput == "")
    {
        exit(0);
    }
    // Sonu�lar� kontrol et
   if (res->next()) {
            // Banned de�eri kontrol et
            string banned = res->getString("status");
            if (banned == "banned") {
                // Kullan�c� banl�, bilgilendir ve program� kapat
                std::cout << "You are banned. Please contact support for further assistance." << std::endl;
                Sleep(3000);
                exit(0);
            }

            // HWID de�eri bo� mu kontrol et
            std::string hwid = res->getString("hwid");
            if (hwid.empty()) {

                pstmt = con->prepareStatement("UPDATE `keys` SET `status` = 'activated' WHERE `key` = ?");
                pstmt->setString(1, userInput);
                pstmt->executeUpdate();
                // HWID de�eri bo�sa, bilgisayar�n UUID de�erini al ve SHA-512 ile hashle
                std::string computerUUID = getComputerUUID();
                std::string hashedUUID = SHA512Hash(computerUUID);

                // SQL sorgusunu haz�rla
                pstmt = con->prepareStatement("UPDATE `keys` SET `hwid` = ? WHERE `key` = ?");
                pstmt->setString(1, hashedUUID);
                pstmt->setString(2, userInput);

                // Sorguyu �al��t�r
                pstmt->executeUpdate();

                std::cout << "" << std::endl;
            }
            else {
                // HWID de�eri dolu ise, bilgisayar�n UUID de�erini al, SHA-512 ile hashle ve veritaban�ndaki ile kar��la�t�r
                std::string computerUUID = getComputerUUID();
                std::string hashedUUID = SHA512Hash(computerUUID);

                if (hwid == hashedUUID) {
                    // Kullan�c� banl� de�il ve HWID do�ru, kontrol etEndDate fonksiyonunu �al��t�r
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

        // Kaynaklar� temizle
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