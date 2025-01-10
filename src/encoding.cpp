#include "encoding.h"

#include <stdexcept>
#include <iconv.h>

std::vector<BYTE> utf8ToUtf16le(const std::string& utf8) {
    // Initialize iconv for UTF-8 to UTF-16LE conversion
    iconv_t conv = iconv_open("UTF-16LE", "UTF-8");
    if (conv == (iconv_t)-1) {
        throw std::runtime_error("iconv_open failed: Cannot initialize converter");
    }

    const char* input = utf8.c_str();
    size_t input_bytes_left = utf8.size() + 1; // Include null terminator
    
    // 2 bytes per UTF-8 character
    size_t output_bytes_left = input_bytes_left * 2;
    std::vector<BYTE> output(output_bytes_left);
    char* output_ptr = reinterpret_cast<char*>(output.data());

    // Perform the conversion
    size_t result = iconv(conv, const_cast<char**>(&input), &input_bytes_left, &output_ptr, &output_bytes_left);
    if (result == (size_t)-1) {
        iconv_close(conv);
        throw std::runtime_error("iconv conversion failed");
    }

    // Calculate the actual size of the converted data
    output.resize(output.size() - output_bytes_left);

    // Clean up iconv
    iconv_close(conv);

    return output;
}

std::vector<unsigned short> utf8ToUnicode(const std::string& utf8) {
    // Initialize iconv for UTF-8 to UTF-16LE conversion
    iconv_t conv = iconv_open("UTF-16LE", "UTF-8");
    if (conv == (iconv_t)-1) {
        throw std::runtime_error("iconv_open failed: Cannot initialize converter");
    }

    const char* input = utf8.c_str();
    size_t input_bytes_left = utf8.size();
    
    // 2 bytes per UTF-8 character + null terminator
    size_t output_bytes_left = (input_bytes_left + 1) * 2;
    std::vector<unsigned short> output(input_bytes_left + 1);
    char* output_ptr = reinterpret_cast<char*>(output.data());

    // Perform the conversion
    size_t result = iconv(conv, const_cast<char**>(&input), &input_bytes_left, &output_ptr, &output_bytes_left);
    if (result == (size_t)-1) {
        iconv_close(conv);
        throw std::runtime_error("iconv conversion failed");
    }

    // Calculate the actual size of the converted data
    //output.resize(output.size() - output_bytes_left);

    // Clean up iconv
    iconv_close(conv);

    return output;
}

std::string utf16leToString(const CERTTRANSBLOB& ctbString) {
    if (!ctbString.pb || ctbString.cb == 0) {
        return std::string();
    }

    // Initialize iconv
    iconv_t conv = iconv_open("UTF-8", "UTF-16LE");
    if (conv == (iconv_t)-1) {
        throw std::runtime_error("iconv_open failed: Cannot initialize converter");
    }

    // Input buffer: UTF-16LE data
    const char* input = reinterpret_cast<const char*>(ctbString.pb);
    size_t input_bytes_left = ctbString.cb;

    // Estimate output size: UTF-8 is twice the size maybe sometimes hopefully.
    size_t output_bytes_left = input_bytes_left * 2;
    std::vector<char> output_buffer(output_bytes_left);
    char* output_ptr = output_buffer.data();

    // Perform the conversion
    size_t result = iconv(conv, const_cast<char**>(&input), &input_bytes_left, &output_ptr, &output_bytes_left);
    if (result == (size_t)-1) {
        iconv_close(conv);
        throw std::runtime_error("iconv conversion failed");
    }

    // Clean up iconv
    iconv_close(conv);

    return std::string(output_buffer.data(), output_buffer.size() - output_bytes_left);
}