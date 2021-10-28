#include<iostream>
#include<vector>
#include<string>
#include<map>
#include<regex>
#include<sstream>
#include<filesystem>
#include<fstream>
#include<utility>

namespace fs = std::filesystem;
using namespace std;


class SnmpOidDb {

public:

    // последовательность индексов OID пользователя
    vector<int> user_int_oid;

    // конструктор
    SnmpOidDb();

    // методы класса

    // получение и обработка нужной информации
    void parse_Mib(const string& dir);

   // map<pair<string, int>, string> loadMib();

    // поиск OID по базе и получение имени соответствующего узла
    string oid_Name(string& oid);

    

private:

    // map<pair<родитель, номер дочернего узла>, дочерний узел> 
    map<pair<string, int>, string> oid_info;

};












