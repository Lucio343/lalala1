// =============================================================================
// Парсер Nmap XML — высокопроизводительный разбор на C++
// Компиляция: g++ -O2 -std=c++17 -o nmap_parser nmap_parser.cpp -lxml2
// Запуск: ./nmap_parser nmap_output.xml
// =============================================================================

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <libxml/parser.h>
#include <libxml2/libxml/tree.h>

struct Port {
    int portid;
    std::string protocol;
    std::string state;
    std::string service;
    std::string version;
};

struct Host {
    std::string address;
    std::string hostname;
    std::vector<Port> ports;
};

// Рекурсивный обход XML-дерева
void parseHost(xmlNode* node, Host& host) {
    for (xmlNode* cur = node; cur; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE) {
            std::string name = (const char*)cur->name;
            
            if (name == "address") {
                xmlChar* addr = xmlGetProp(cur, (const xmlChar*)"addr");
                if (addr) {
                    host.address = (const char*)addr;
                    xmlFree(addr);
                }
            }
            else if (name == "hostname") {
                xmlChar* hn = xmlGetProp(cur, (const xmlChar*)"name");
                if (hn) {
                    host.hostname = (const char*)hn;
                    xmlFree(hn);
                }
            }
            else if (name == "port") {
                Port p;
                xmlChar* portid = xmlGetProp(cur, (const xmlChar*)"portid");
                xmlChar* protocol = xmlGetProp(cur, (const xmlChar*)"protocol");
                if (portid) { p.portid = std::stoi((const char*)portid); xmlFree(portid); }
                if (protocol) { p.protocol = (const char*)protocol; xmlFree(protocol); }
                
                // Обход дочерних элементов порта
                for (xmlNode* child = cur->children; child; child = child->next) {
                    if (child->type == XML_ELEMENT_NODE) {
                        std::string cname = (const char*)child->name;
                        if (cname == "state") {
                            xmlChar* state = xmlGetProp(child, (const xmlChar*)"state");
                            if (state) { p.state = (const char*)state; xmlFree(state); }
                        }
                        else if (cname == "service") {
                            xmlChar* svc = xmlGetProp(child, (const xmlChar*)"name");
                            xmlChar* ver = xmlGetProp(child, (const xmlChar*)"version");
                            if (svc) { p.service = (const char*)svc; xmlFree(svc); }
                            if (ver) { p.version = (const char*)ver; xmlFree(ver); }
                        }
                    }
                }
                host.ports.push_back(p);
            }
        }
        parseHost(cur->children, host);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <nmap_output.xml>" << std::endl;
        return 1;
    }
    
    xmlDoc* doc = xmlReadFile(argv[1], NULL, 0);
    if (!doc) {
        std::cerr << "Ошибка: не удалось открыть файл " << argv[1] << std::endl;
        return 1;
    }
    
    xmlNode* root = xmlDocGetRootElement(doc);
    std::vector<Host> hosts;
    
    for (xmlNode* cur = root->children; cur; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE && std::string((const char*)cur->name) == "host") {
            Host h;
            parseHost(cur->children, h);
            hosts.push_back(h);
        }
    }
    
    // Вывод в JSON-подобном формате
    std::cout << "{\"hosts\": [" << std::endl;
    for (size_t i = 0; i < hosts.size(); ++i) {
        std::cout << "  {\"address\": \"" << hosts[i].address << "\", ";
        std::cout << "\"hostname\": \"" << hosts[i].hostname << "\", ";
        std::cout << "\"ports\": [" << std::endl;
        for (size_t j = 0; j < hosts[i].ports.size(); ++j) {
            auto& p = hosts[i].ports[j];
            std::cout << "    {\"port\": " << p.portid 
                      << ", \"protocol\": \"" << p.protocol 
                      << "\", \"state\": \"" << p.state 
                      << "\", \"service\": \"" << p.service 
                      << "\", \"version\": \"" << p.version << "\"}";
            if (j < hosts[i].ports.size() - 1) std::cout << ",";
            std::cout << std::endl;
        }
        std::cout << "  ]}";
        if (i < hosts.size() - 1) std::cout << ",";
        std::cout << std::endl;
    }
    std::cout << "]}" << std::endl;
    
    xmlFreeDoc(doc);
    xmlCleanupParser();
    return 0;
}
