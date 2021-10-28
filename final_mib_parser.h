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

    // ������������������ �������� OID ������������
    vector<int> user_int_oid;

    // �����������
    SnmpOidDb();

    // ������ ������

    // ��������� � ��������� ������ ����������
    void parse_Mib(const string& dir);

   // map<pair<string, int>, string> loadMib();

    // ����� OID �� ���� � ��������� ����� ���������������� ����
    string oid_Name(string& oid);

    

private:

    // map<pair<��������, ����� ��������� ����>, �������� ����> 
    map<pair<string, int>, string> oid_info;

};












