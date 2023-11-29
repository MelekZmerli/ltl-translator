#include "utils.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>

// remove non-alphabetic characters, numbers and '_'
std::string removeNoneAlnum(const std::string& inp_string) {
  std::string s = inp_string;
  for (int i = 0; i < s.size(); i++) {
    if ((s[i] < 'A' || s[i] > 'Z') && (s[i] < 'a' || s[i] > 'z') &&
        (s[i] < '0' || s[i] > '9') && s[i] != '_') {
      s.erase(i, 1);
      i--;
    }
  }
  return s;
}

bool isInteger(const std::string& s) {
  if (s.empty() || ((!isdigit(s[0])) && (s[0] != '-') && (s[0] != '+')))
    return false;

  char* p;
  strtol(s.c_str(), &p, 10);

  return (*p == 0);
}

void debug_info(const std::string& _info) {
  if (std::getenv("SIF_DEBUG") != nullptr) {
    std::cerr << "[SIF_DEBUG_INFO]" << _info << "\n";
  }
}

// trim string from left side
// from
// https://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring
void ltrim(std::string& _str) {
  _str.erase(_str.begin(), std::find_if(_str.begin(), _str.end(), [](int ch) {
               return !std::isspace(ch);
             }));
}

void ltrim_ex(std::string& _str) {
  _str.erase(_str.begin(), std::find_if(_str.begin(), _str.end(), [](int ch) {
               return !std::isspace(ch) && !(ch == '\t') && !(ch == '\n');
             }));
}

// trim string from right side
// from
// https://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring
void rtrim(std::string& _str) {
  _str.erase(std::find_if(_str.rbegin(), _str.rend(),
                          [](int ch) { return !std::isspace(ch); })
                 .base(),
             _str.end());
}

void rtrim_ex(std::string& _str) {
  _str.erase(std::find_if(_str.rbegin(), _str.rend(),
                          [](int ch) {
                            return !std::isspace(ch) && !(ch == '\t') &&
                                   !(ch == '\n');
                          })
                 .base(),
             _str.end());
}

// trim from both ends (in place)
// from
// https://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring
void trim(std::string& _str) {
  ltrim(_str);
  rtrim(_str);
}

void trim_ex(std::string& _str) {
  ltrim_ex(_str);
  rtrim_ex(_str);
}

// trim from left side but no overwrite
// from
// https://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring
std::string ltrim_copy(const std::string& _str) {
  return _str.substr(_str.find_first_not_of(' '));
}

// trim from right side but no overwrite
// from
// https://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring
std::string rtrim_copy(const std::string& _str) {
  return _str.substr(0, _str.find_last_not_of(' ') + 1);
}

// trim from both sides but no overwrite
// from
// https://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring
std::string trim_copy(const std::string& _str) {
  return _str.substr(
      _str.find_first_not_of(' '),
      _str.find_last_not_of(' ') - _str.find_first_not_of(' ') + 1);
}

// from
// https://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c
std::vector<std::string> split(const std::string& _str,
                               const std::string& _delimiter) {
  std::vector<std::string> result;
  std::string str = std::string(_str);
  size_t pos = 0;
  std::string token;
  while ((pos = str.find(_delimiter)) != std::string::npos) {
    token = str.substr(0, pos);
    result.push_back(token);
    str.erase(0, pos + _delimiter.length());
  }
  result.push_back(str);

  return result;
}

// spilt a string to maximum '_num' substring based on _delimiter
std::vector<std::string> split_ex(const std::string& _str,
                                  const std::string& _delimiter,
                                  const size_t& _num) {
  std::vector<std::string> result;
  std::string str = std::string(_str);
  size_t pos = 0;
  std::string token;
  int count = 1;
  while ((pos = str.find(_delimiter)) != std::string::npos && count < _num) {
    token = str.substr(0, pos);
    result.push_back(token);
    str.erase(0, pos + _delimiter.length());
    count++;
  }
  result.push_back(str);

  return result;
}
/** Retrieve an element of the string by delimiter
 */
std::string retrieve_string_element(const std::string& _str,
                                    const unsigned int& _index,
                                    const std::string& _delimiter) {
  std::string new_str = std::string(_str);
  trim_ex(new_str);
  std::vector<std::string> v_str = split(new_str, _delimiter);
  if (_index < v_str.size()) {
    return v_str[_index];
  } else {
    return "";
  }
}

/** Extract the string by edge
 */
std::string substr_by_edge(const std::string& _str, const std::string& _left,
                           const std::string& _right) {
  auto left = _str.find(_left);
  auto right = _str.rfind(_right);
  if (left == std::string::npos || right == std::string::npos) {
    return "";
  } else {
    return _str.substr(_left.length() + left, right - _left.length() - left);
  }
}

// from
// https://stackoverflow.com/questions/3418231/replace-part-of-a-string-with-another-string
void str_replace_all(std::string& _str, const std::string& _from,
                     const std::string& _to) {
  if (_from.empty()) {
    return;
  }
  size_t start_pos = 0;
  while ((start_pos = _str.find(_from, start_pos)) != std::string::npos) {
    _str.replace(start_pos, _from.length(), _to);
    start_pos += _to.length();  // In case 'to' contains 'from', like replacing
                                // 'x' with 'yx'
  }
}

std::map<std::string, std::string> parse_visitor_args(
    const std::string& _args) {
  auto values = split(_args, " ");
  std::map<std::string, std::string> result;
  for (auto it = values.begin(); it != values.end(); ++it) {
    auto pair = split(*it, "=");
    if (pair.size() != 2) {
      continue;
    }
    result[pair[0]] = pair[1];
  }
  return result;
}

// trim string and get first substring that only contain alphabetic characters,
// numbers and '_'
std::string get_first_alpha_only_string(const std::string& _str) {
  std::string str = std::string(_str);
  trim_ex(str);
  int pos = 0;
  for (int i = 0; i < str.size(); i++) {
    if ((str[i] < 'A' || str[i] > 'Z') && (str[i] < 'a' || str[i] > 'z') &&
        (str[i] < '0' || str[i] > '9') && str[i] != '_') {
      pos = i;
      break;
    }
  }
  return str.substr(0, pos);
}

std::string to_upper_copy(const std::string& _str) {
  std::string new_str = _str;
  std::transform(new_str.begin(), new_str.end(), new_str.begin(),
                 [](unsigned char c) { return std::toupper(c); });
  return new_str;
}

std::string join(const std::vector<std::string>& lst,
                 const std::string& delim) {
  std::string ret;
  for (const auto& s : lst) {
    if (!ret.empty())
      ret += delim;
    ret += s;
  }
  return ret;
}

std::string repeat_word(const std::string& word, int n) {
  std::string tmp = word;
  for (int i = 1; i < n; i++) {
    tmp += "," + word;
  }
  return tmp;
}

std::string generate_seq(int from, int to) {
  std::string tmp = std::to_string(from);
  for (int k = from + 1; k <= to; k++) {
    tmp += "," + std::to_string(k);
  }
  return tmp;
}