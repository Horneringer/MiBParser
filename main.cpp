#include<iostream>
#include "final_mib_parser.h"

using namespace std;


// собрать OID 1.3.6.1.6.3 - выполнено
// собрать OID 1.3.6.1.2.1.1.9.1.2.2

int main(int argc, char** argv) {

    SnmpOidDb db;
    
    string check_oid = "1.3.6.1.4.1.3417.2.11.2.1.6";
    /*string check_oid2 = "1.3.6.1.2.1.6.9"; 
    string check_oid3 = "1.3.6.1.2.1.1.9.1.2.2";*/

    db.parse_Mib("D:/VisualStudioProjects/test_mib_files");


    auto oidName = db.oid_Name(check_oid);
    //auto oidName2 = db.oid_Name(check_oid);
   

    cout << oidName << endl;
    //cout << oidName2 << endl;

   
    return 0;
}

    



