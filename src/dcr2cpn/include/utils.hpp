#ifndef UTILS_H_
#define UTILS_H_

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <list>
#include <map>
#include <string>
#include <vector>
#include <cctype>

void debug_info(const std::string& _info);

// remove all none alpha or number or '_' charaters from string
std::string removeNoneAlnum(const std::string& inp_string);

// trim string from left side
void ltrim(std::string& _str);
void ltrim_ex(std::string& _str);
// trim string from right side
void rtrim(std::string& _str);
void rtrim_ex(std::string& _str);
// trim from both ends (in place)
void trim(std::string& _str);
void trim_ex(std::string& _str);
// trim from left side but no overwrite
std::string ltrim_copy(const std::string& _str);

// trim from right side but no overwrite
std::string rtrim_copy(const std::string& _str);

// trim from both sides but no overwrite
std::string trim_copy(const std::string& _str);

std::vector<std::string> split(const std::string& _str, const std::string& _delimiter);

std::vector<std::string> split_ex(const std::string& _str, const std::string& _delimiter, const size_t& _num);

// Get the _index[th] element from a string split by _c
std::string retrieve_string_element(const std::string& _str, const unsigned int& _index, const std::string& _delimiter);

std::string substr_by_edge(const std::string& _str, const std::string& _left, const std::string& _right);

//from https://stackoverflow.com/questions/3418231/replace-part-of-a-string-with-another-string
void str_replace_all(std::string& _str, const std::string& _from, const std::string& _to);

bool isInteger(const std::string & s);

std::map<std::string, std::string> parse_visitor_args(const std::string& _args);

std::string get_first_alpha_only_string(const std::string& _str);

std::string to_upper_copy(const std::string& _str);

std::string join(const std::vector<std::string> &lst, const std::string &delim);
#endif 