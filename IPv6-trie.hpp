#include <bitset>
#include <memory>
#include <iostream>
#include <algorithm>
#include <arpa/inet.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <bitset>
#include <memory>
#include <string>
#include <iostream>
#include <nlohmann/json.hpp>
#include <fstream>

struct ResponseRates {
    double default_rate = 0.0;
    double eui_rate = 0.0;
    double lower_rate = 0.0;
    double higher_rate = 0.0;
};

inline constexpr uint8_t LAST_RELEVANT_BITS = 10;


class Node {
public:
    Node(const std::bitset<128> &prefix = {}, size_t length = 0, bool isReal = false);

    void insertPrefixesFromJSON(const std::string &filePath);

    double getResponseRateForAddress(const std::string &addressStr) const;

    std::string matchFromString(const std::string &addressStr) const;

    void printTrie(int level = 0) const;

    void setRates(const ResponseRates &rates) { responseRates = rates; }

private:
    std::bitset<128> prefix;
    size_t prefixLength;
    bool isRealPrefix = false;
    ResponseRates responseRates;

    std::unique_ptr<Node> left;
    std::unique_ptr<Node> right;

    Node *insert(const std::bitset<128> &newPrefix, size_t newLength);

    Node *find(const std::bitset<128> &address, size_t depth = 0);
};

Node::Node(const std::bitset<128> &prefix, size_t length, bool isReal)
        : prefix(prefix), prefixLength(length), isRealPrefix(isReal) {}

size_t commonPrefixLength(const std::bitset<128> &a, const std::bitset<128> &b) {
    size_t common = 0;
    while (common < 128 && a[127 - common] == b[127 - common]) {
        ++common;
    }
    return common;
}

std::pair<std::bitset<128>, size_t> parseIPv6(const std::string &input) {
    size_t slashPos = input.find('/');
    if (slashPos == std::string::npos)
        throw std::invalid_argument("Invalid IPv6 prefix: missing '/'");

    std::string addrStr = input.substr(0, slashPos);
    size_t prefixLength = std::stoul(input.substr(slashPos + 1));

    if (prefixLength > 128)
        throw std::invalid_argument("Prefix length out of range");

    std::bitset<128> bits;
    uint8_t raw[16];

    if (inet_pton(AF_INET6, addrStr.c_str(), raw) != 1)
        throw std::invalid_argument("Invalid IPv6 address");

    for (int byte = 0; byte < 16; ++byte) {
        for (int bit = 0; bit < 8; ++bit) {
            bool bitVal = (raw[byte] >> (7 - bit)) & 1;
            bits[127 - (byte * 8 + bit)] = bitVal;
        }
    }

    return {bits, prefixLength};
}

std::string bitsetToIPv6(const std::bitset<128> &bits) {
    uint8_t raw[16] = {0};

    for (int byte = 0; byte < 16; ++byte) {
        for (int bit = 0; bit < 8; ++bit) {
            if (bits[127 - (byte * 8 + bit)]) {
                raw[byte] |= (1 << (7 - bit));
            }
        }
    }

    char str[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, raw, str, INET6_ADDRSTRLEN)) {
        return "<invalid>";
    }
    return std::string(str);
}


Node *Node::insert(const std::bitset<128> &newPrefix, size_t newLength) {
    size_t common = 0;
    while (common < 128 &&
           common < std::min(prefixLength, newLength) &&
           prefix[127 - common] == newPrefix[127 - common]) {
        ++common;
    }

    if (common == prefixLength && common == newLength) {
        isRealPrefix = true;
        return this;
    }

    if (common == prefixLength && newLength > prefixLength) {
        bool bit = newPrefix[127 - prefixLength];
        std::unique_ptr<Node> &child = bit ? right : left;

        if (!child) {
            child = std::make_unique<Node>(newPrefix, newLength, true);
            return child.get();
        } else {
            return child->insert(newPrefix, newLength);
        }
    }

    // Split current node
    std::bitset<128> oldPrefix = prefix;
    size_t oldLength = prefixLength;
    bool oldReal = isRealPrefix;

    prefixLength = common;
    isRealPrefix = false;

    auto existing = std::make_unique<Node>(oldPrefix, oldLength, oldReal);
    existing->left = std::move(left);
    existing->right = std::move(right);
    existing->responseRates = this->responseRates;
    this->responseRates = ResponseRates();

    left = nullptr;
    right = nullptr;

    bool existingBit = oldPrefix[127 - common];
    if (existingBit)
        right = std::move(existing);
    else
        left = std::move(existing);

    bool newBit = newPrefix[127 - common];
    std::unique_ptr<Node> &branch = newBit ? right : left;

    if (!branch) {
        branch = std::make_unique<Node>(newPrefix, newLength, true);
        return branch.get();
    } else {
        Node *inserted = branch->insert(newPrefix, newLength);
        if (!inserted->isRealPrefix) {
            inserted->isRealPrefix = true;  // Ensure it's marked
        }
        return inserted;
    }

}

Node *Node::find(const std::bitset<128> &address, size_t depth) {
    Node *current = this;
    while (current) {
        bool matches = true;
        for (size_t i = 0; i < current->prefixLength; ++i) {
            if (address[127 - i] != current->prefix[127 - i]) {
                matches = false;
                break;
            }
        }

        if (!matches) return nullptr;
        if (current->isRealPrefix && current->prefixLength + depth == 128)
            return current;

        bool bit = address[127 - current->prefixLength];
        current = bit ? current->right.get() : current->left.get();
    }
    return nullptr;
}


void Node::printTrie(int level) const {
    for (int i = 0; i < level; ++i)
        std::cout << "  ";

    std::string ipv6Text = bitsetToIPv6(prefix);
    std::cout << ipv6Text << "/" << prefixLength;

    if (isRealPrefix)
        std::cout << " [INSERTED]";
    else
        std::cout << " [STRUCTURAL]";

    std::cout << "\n";

    if (left) {
        for (int i = 0; i < level; ++i) std::cout << "  ";
        std::cout << "↙\n";
        left->printTrie(level + 1);
    }

    if (right) {
        for (int i = 0; i < level; ++i) std::cout << "  ";
        std::cout << "↘\n";
        right->printTrie(level + 1);
    }
}


void Node::insertPrefixesFromJSON(const std::string &filePath) {
    std::ifstream in(filePath);
    if (!in.is_open()) {
        throw std::runtime_error("Failed to open JSON file: " + filePath);
    }

    nlohmann::json j;
    in >> j;

    if (!j.contains("subnets") || !j["subnets"].is_array()) {
        throw std::runtime_error("JSON does not contain a valid 'subnets' array");
    }

    for (const auto &subnet: j["subnets"]) {
        if (!subnet.contains("ipv6_prefix")) continue;

        std::string prefixStr = subnet["ipv6_prefix"];
        try {
            auto [bits, len] = parseIPv6(prefixStr);
            Node *node = insert(bits, len);
            ResponseRates rates;
            rates.default_rate = subnet.value("default_response_rate", 0.0);
            rates.eui_rate = subnet.value("EUI_response_rate", 0.0);
            rates.lower_rate = subnet.value("lower_response_rate", 0.0);
            rates.higher_rate = subnet.value("higher_response_rate", 0.0);
            node->setRates(rates);
            //std::cout << "Inserted prefix: " << prefixStr << "\n";
        } catch (const std::exception &e) {
            std::cerr << "Failed to insert '" << prefixStr << "': " << e.what() << "\n";
        }
    }
}

const bool isEUI64(const std::bitset<128> &address) {
    auto addr = address;
    // ignore last 24 bits so ff:fe is at the end of the address.
    addr >>= 24;
    // Bits 64 to 71 and 72 to 79 correspond to bytes 8 and 9 
    std::bitset<128> bit_mask("1111111111111111");

    addr ^= bit_mask;

    addr &= bit_mask;
    return (addr == 1);
};


const bool isLowerByte(const std::bitset<128> &address, const std::bitset<128> &prefix, int prefix_len) {
    if (prefix_len <= LAST_RELEVANT_BITS) return false;

    std::bitset<128> diff = address ^ prefix;

    // Only the lowest LAST_RELEVANT_BITS may differ
    for (int i = LAST_RELEVANT_BITS + 1; i < 128; ++i) {
        if (diff[i]) return false;
    }
    return diff.any(); // at least one low bit must differ
}

const bool isHigherByte(const std::bitset<128> &address, const std::bitset<128> &prefix, int prefix_len) {
    if (prefix_len <= LAST_RELEVANT_BITS) return false;

    std::bitset<128> diff = address ^ prefix;

    diff >>= LAST_RELEVANT_BITS;
    auto mask = std::bitset<128>((1ULL << (prefix_len - LAST_RELEVANT_BITS)) - 1);
    return (diff == mask);
}


double Node::getResponseRateForAddress(const std::string &addressStr) const {
    std::bitset<128> address;
    uint8_t raw[16];

    /*
     * Pack the 16 big-endian bytes from inet_pton into a bitset<128> where
     * bit 127 is the address's MSB and bit 0 its LSB.
    **/

    uint64_t hi, lo;
    std::memcpy(&hi, raw, 8);
    std::memcpy(&lo, raw + 8, 8);
    hi = __builtin_bswap64(hi);
    lo = __builtin_bswap64(lo);

    address = std::bitset<128>(hi);
    address <<= 64;
    address |= std::bitset<128>(lo);

    const Node *best = nullptr;
    const Node *current = this;
    /**
     * Since we iterate in a trie, we can skip all bits checked for the last prefix.
     * For a full depth trie this leads to a improvement of n(n-1):2.
     */
    uint64_t lastPrefixLength = 0;
    while (current) {
        bool matches = true;
        // skip all bits already checked.
        for (size_t i = lastPrefixLength; i < current->prefixLength; ++i) {
            if (address[127 - i] != current->prefix[127 - i]) {
                matches = false;
                break;
            }
        }

        if (!matches) break;

        if (current->isRealPrefix) {
            best = current;
        }

        if (current->prefixLength == 128) break;
        lastPrefixLength = current->prefixLength;
        bool bit = address[127 - current->prefixLength];
        current = bit ? current->right.get() : current->left.get();
    }

    if (!best) {
        //std::cout << "No prefix match found for " << addressStr << "\n";
        return 0.0;
    }

    // Print the matched node's prefix and length
    //std::cout << "Matched node: " << bitsetToIPv6(best->prefix) << "/" << best->prefixLength
    //        << " for address: " << addressStr << "\n";


    const auto &rates = best->responseRates;

    if (isEUI64(address)) {
        return rates.eui_rate;
    } else if (isLowerByte(address, best->prefix, best->prefixLength)) {
        //std::cout << addressStr << "\n";;
        return rates.lower_rate;
    } else if (isHigherByte(address, best->prefix, best->prefixLength)) {
        //std::cout << addressStr << "\n";;
        return rates.higher_rate;
    }

    return rates.default_rate;
}