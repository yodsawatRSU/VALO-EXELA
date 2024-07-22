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
#include <ctime> // Bu kütüphaneyi eklemeyi unutma
#include "sakso.h"
#include <sstream>
#pragma comment(lib, "IPHLPAPI.lib")
// HWID (UUID) ve Ekran Kartý Modelini Al


void cheatss()
{
    sql::mysql::MySQL_Driver* driver;
    sql::Connection* con;
    int baba = 89;
    int baba1 = 116;
    int baba3 = 27;
    int baba4 = 231;

    // MySQL veritabanýna baðlanmak için gerekli bilgiler
    std::string user1 = loginning2();
    std::string user2 = loginning();
    std::string host = std::to_string(baba) + "." + std::to_string(baba1) + "." + std::to_string(baba3) + "." + std::to_string(baba4);

    // MySQL veritabanýna baðlanmak için gerekli bilgiler
    std::string user = "MemoryLeakTracker";
    std::string password = user1 + user2 + "!";
    std::string database = "AppConfigStore";

    try {
        driver = sql::mysql::get_mysql_driver_instance();

        // Veritabanýna baðlan
        con = driver->connect(host, user, password);

        // Kullanýlacak veritabanýný seç
        con->setSchema(database);
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

    sql::PreparedStatement* pstmt;
    pstmt = con->prepareStatement("SELECT * FROM `keys` WHERE `key` = ?");
    pstmt->setString(1, userInput);

    // Sorguyu çalýþtýr
    sql::ResultSet* res = pstmt->executeQuery();
    if (userInput.empty())	
    {
        BlueScreen();

    }
    if (userInput == "")
    {
        exit(0);
    }
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