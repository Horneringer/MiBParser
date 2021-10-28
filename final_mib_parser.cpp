#include "final_mib_parser.h"

ostream& operator<<(ostream& stream, vector<int>& vec) {

    for (auto i = 0; i < vec.size(); i++) {

        stream << vec[i] << " ";

    }
    return stream;
}

// перегрузка вывода вектора

ostream& operator<<(ostream& stream, vector<string>& vec) {

    for (auto i = 0; i < vec.size(); i++) {

        stream << vec[i] << " ";

    }
    return stream;
}

// перегрузка вывода 2d вектора
ostream& operator<<(ostream& stream, vector<vector<string>>& vec_2d) {

    for (size_t row{}; row < vec_2d.size(); ++row) {

        for (size_t column{}; column < vec_2d[row].size(); ++column) {

            stream << vec_2d[row][column] << " ";
            
        }

        stream << endl;
    }

    return stream;
}

// перегрузка вывода словаря
ostream& operator<<(ostream& stream, map<string, string>& mp) {

    for (auto item : mp) {

        stream << item.first << " : " << item.second << endl;
    }

    return stream;
}

// перегрузка вывода map<pair<>,string>

ostream& operator<<(ostream& stream, map<pair<string, int>, string> mp_p) {

    for (const auto& item : mp_p) {

        auto key_pair = item.first;

        stream << key_pair.first << " " << key_pair.second << " " << item.second << endl;
    }

    return stream;
}

ostream& operator<<(ostream& stream, map<pair<string, string>, string> mp_p) {

    for (const auto& item : mp_p) {

        auto key_pair = item.first;

        stream << key_pair.first << " " << key_pair.second << " " << item.second << endl;
    }

    return stream;
}

// конструктор

SnmpOidDb::SnmpOidDb() {


}

void SnmpOidDb::parse_Mib(const string& dir) {

    vector<string> result_strings;

    // 2d вектор с доступом к каждому узлу и индесам
    vector<vector<string>> external_oids_vec;

    // регулярка для OBJECT IDENTIFIER
    regex reg = regex("[-\\w]+\\s*OBJECT IDENTIFIER(?!,)\\s*::=\\s*\\{\\s*(?!\\d+)[-\\w]+\\s*\\d+\\s*\\}|(::=\\s*\\{\\s*(?!\\d+)[-\\w]+\\s*\\d+\\s*\\}(?!\\s*this))|([-\\w]+\\s*OBJECT-TYPE(?!\"|,|\\s*[a-zA-Z]))|([-\\w]+\\s*NOTIFICATION-TYPE(?!,|\\s*[A-Z]))|([-\\w]+\\s*OBJECT-IDENTITY(?!,|\\s*[A-Z]|STATUS))|([-\\w]+\\s*MODULE-COMPLIANCE(?!,|\\s))|([-\\w]+\\s*NOTIFICATION-GROUP(?!,))|([-\\w]+\\s*OBJECT-GROUP(?!,))|([-\\w]+\\s*MODULE-IDENTITY(?!,|\\s*[A-Z]))");

    string line;

    ifstream in;

    // список всех строк, совпадающих с регулярками

    for (auto item : fs::directory_iterator(dir)) {

        in.open(item.path().string());

        // если файл не найден
        if (!in) {

            cout << "Not found: " << item.path().filename().string() << endl;
        }


        //считывание из файла нужной информации по OID
        while (getline(in, line)) {

            // если совпадение с регуляркой найдено
            if (regex_search(line, reg)) {

                line = regex_replace(line, regex("\\s+"), " ");

                if (line.find("the NOTIFICATION-TYPE") != string::npos)
                    continue;

                if (line.find(",") != string::npos)
                    continue;

                if (line._Starts_with("--") || line._Starts_with(" --") || line._Starts_with("zeroDotZero") || line._Starts_with("nlmLogNotificationID"))
                    continue;

                size_t pos = line.find("--");
                if (pos != string::npos) {

                    line.erase(pos, line.length());

                }
                
                // замена нескольких пробелов одним
                line = regex_replace(line, regex("\\s+"), " ");
                line = regex_replace(line, regex("\\t+"), "");

                result_strings.push_back(line);  
            }
        }

        for (auto i = 0; i < result_strings.size(); i++) {

            if (result_strings[i].find(" :") == 0 || result_strings[i].find(":") == 0)   {

                // соединяет 2 половины строки в 1 
                result_strings[static_cast<unsigned __int64>(i) - 1].append(result_strings[i]);

                // удаление копии с позиции i
                result_strings.erase(result_strings.begin() + i);
  
            }
        }

        const char* delim = ":";
        string::size_type pos{};

        for (auto i = 0; i < result_strings.size(); i++) {

            // удаление подстроки с кавычкой до символа : и соединение в полную строку
            if (result_strings[i]._Starts_with(" \"") || result_strings[i]._Starts_with(" be")) {

                pos = result_strings[i].find_first_of(delim, pos);

                result_strings[i].erase(0, pos);

                result_strings[static_cast<unsigned __int64>(i) - 1].append(result_strings[i]);

                result_strings.erase(result_strings.begin() + i);
            }

            if (result_strings[i]._Starts_with("SYNTAX")) {

                result_strings.erase(result_strings.begin() + i);
            }

            result_strings[i] = regex_replace(result_strings[i], regex("--|IANA DHKEY-CHANGE 101|obsolete|unlucky|OBJECT-IDENTITY|MODULE-IDENTITY|OBJECT IDENTIFIER|OBJECT-TYPE|OBJECT-GROUP|NOTIFICATION-GROUP|NOTIFICATION-TYPE|MODULE-COMPLIANCE|::=|\\}|\\{|:|="), "");
            result_strings[i] = regex_replace(result_strings[i], regex("\\s+"), " ");

        }

        in.close();
    }

    // преобразование вектора строк в 2d вектор с 3мя(4мя) основными элементами для сборки OID
    vector<string>tmp_vec;

    // буфер для одной строки массива
    stringstream ss;

    // буфер для хранения отдельных элементов строки
    string tmp;

    for (auto item : result_strings) {

        tmp.clear();
        ss.clear();

        ss << item;

        while (ss >> tmp) {

            tmp_vec.push_back(tmp);
        }

        external_oids_vec.push_back(tmp_vec);
        tmp_vec.clear();
    }

    for (auto i = 0; i < external_oids_vec.size(); i++) {

        for (auto j = 0; j < external_oids_vec[i].size(); j++) {

            oid_info[make_pair(external_oids_vec[i][1], stoi(external_oids_vec[i][2]))] = external_oids_vec[i][0];
        }
    }
}


string SnmpOidDb::oid_Name(string& oid) {

    // итоговая последовательность имен объектов
    string oidName;

    // корневой узел сборки
    string parent = "iso";
    oidName.append(parent);


    // разделитель
    string delim = ".";

    size_t pos = 0;
    string token;

    while ((pos = oid.find(delim)) != string::npos) {
        token = oid.substr(0, pos);
        user_int_oid.push_back(stoi(token));
        oid.erase(0, pos + delim.length());
    }

    user_int_oid.push_back(stoi(oid));

    cout << user_int_oid << endl;

    for (auto i = 1; i < user_int_oid.size(); i++) {

        pair key_pair = make_pair(parent, user_int_oid[i]);

            if (oid_info.count(key_pair)) {

                parent = oid_info[key_pair];

                oidName.append(delim).append(parent);
            } 
    }

    // очистка вектора int для последующих запросов
    user_int_oid.clear();

    return oidName;

}





