#pragma once

#include <string>
#include <vector>

#include "ms-icpr.h"

std::string utf16leToString(const CERTTRANSBLOB& ctbString);
std::vector<unsigned short> utf8ToUnicode(const std::string& utf8);
std::vector<BYTE> utf8ToUtf16le(const std::string& utf8);