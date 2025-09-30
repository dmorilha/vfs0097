/* Copyright Daniel Morilha 2025 */

#include <algorithm>
#include <array>
#include <iomanip>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include <cassert>
#include <cmath>

#include <libusb.h>

#include <endian.h>

#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace {
std::ostream & operator << (std::ostream & o, const libusb_error error) {
  switch (error) {
  /** Success (no error) */
  case LIBUSB_SUCCESS:
    o << "LIBUSB_SUCCESS";
    break;

  /** Input/output error */
  case LIBUSB_ERROR_IO:
    o << "LIBUSB_ERROR_IO";
    break;

  /** Invalid parameter */
  case LIBUSB_ERROR_INVALID_PARAM:
    o << "LIBUSB_ERROR_INVALID_PARAM";
    break;

  /** Access denied (insufficient permissions) */
  case LIBUSB_ERROR_ACCESS:
    o << "LIBUSB_ERROR_ACCESS";
    break;

  /** No such device (it may have been disconnected) */
  case LIBUSB_ERROR_NO_DEVICE:
    o << "LIBUSB_ERROR_NO_DEVICE";
    break;

  /** Entity not found */
  case LIBUSB_ERROR_NOT_FOUND:
    o << "LIBUSB_ERROR_NOT_FOUND";
    break;

  /** Resource busy */
  case LIBUSB_ERROR_BUSY:
    o << "LIBUSB_ERROR_BUSY";
    break;

  /** Operation timed out */
  case LIBUSB_ERROR_TIMEOUT:
    o << "LIBUSB_ERROR_TIMEOUT";
    break;

  /** Overflow */
  case LIBUSB_ERROR_OVERFLOW:
    o << "LIBUSB_ERROR_OVERFLOW";
    break;

  /** Pipe error */
  case LIBUSB_ERROR_PIPE:
    o << "LIBUSB_ERROR_PIPE";
    break;

  /** System call interrupted (perhaps due to signal) */
  case LIBUSB_ERROR_INTERRUPTED:
    o << "LIBUSB_ERROR_INTERRUPTED";
    break;

  /** Insufficient memory */
  case LIBUSB_ERROR_NO_MEM:
    o << "LIBUSB_ERROR_NO_MEM";
    break;

  /** Operation not supported or unimplemented on this platform */
  case LIBUSB_ERROR_NOT_SUPPORTED:
    o << "LIBUSB_ERROR_NOT_SUPPORTED";
    break;

  /** Other error */
  case LIBUSB_ERROR_OTHER:
    o << "LIBUSB_ERROR_OTHER";
    break;

  default:
    o << "(unknown error)";
    break;
  };
  return o;
}

std::ostream & operator << (std::ostream & o, const std::span<const uint8_t> & input) {
  for (int i = 0; input.size() > i; i += 16) {
    o << std::hex << std::setfill('0') << std::setw(8) << i << ":";
    for (int j = 0; 16 > j && input.size() > i + j; ++j) {
      if (0 == j % 2) {
        o << " ";
      }
      o << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(input[i + j]);
    }
    o << "\n";
  }
  o << std::dec << std::setw(0);
  o << "(size: " << input.size() << ")\n";
  return o;
}

static constexpr std::span<const uint8_t> nullspan{};
} // end of anonymous namespace

//TODO: replace hardcoded IV with a randomly generated one
struct Cipher {
  using IV = std::vector<uint8_t>;
  using Input = std::span<const uint8_t>;
  using Key = std::vector<uint8_t>;
  using Output = std::vector<uint8_t>;

  enum Mode {
    encrypt,
    decrypt,
    finished,
  };

  EVP_CIPHER_CTX * const context_ = nullptr;
  const std::size_t block_size_ = 0;
  const Key key_;
  Mode mode_ = encrypt;
  IV iv__;
  const std::span<const uint8_t> iv_;
  std::size_t written_ = 0;
  Output output_;

  ~Cipher() {
    assert(nullptr != context_);
    EVP_CIPHER_CTX_free(context_);
  }

  Cipher(const std::vector<uint8_t> & key, const Mode mode = encrypt,
      const std::span<const uint8_t> & iv = nullspan) :
    context_(EVP_CIPHER_CTX_new()),
    block_size_(EVP_CIPHER_get_block_size(EVP_aes_256_cbc())),
    key_(key.begin(), key.end()), mode_(mode), iv_(iv) {
    assert(nullptr != context_);
    assert(0 < block_size_);
    assert(0 == key_.size() % block_size_); // key needs to be a multiple of block size ?
    assert(finished != mode_);

    int result_code = 0;

    if (nullspan.data() == iv_.data()) {
      iv__.resize(0x10);
      {
        const int code = RAND_bytes(iv__.data(), iv__.size());
        assert(1 == code);
      }
      const_cast<std::span<const uint8_t> &>(iv_) = std::span<const uint8_t>(iv__.begin(), iv__.end());
    }

    switch (mode_) {
    case encrypt:
      result_code = EVP_EncryptInit(context_, /* could be any EVP_CIPHER */ EVP_aes_256_cbc(), key_.data(), iv_.data());
      break;

    case decrypt:
      result_code = EVP_DecryptInit(context_, /* could be any EVP_CIPHER */ EVP_aes_256_cbc(), key_.data(), iv_.data());
      break;

    default:
      assert(!"unreachable");
      break;
    }

    assert(1 == result_code);
    result_code = EVP_CIPHER_CTX_set_padding(context_, 0);
    assert(1 == result_code);
    output_.reserve(1024);
  }

  std::span<const uint8_t> iv() const { return iv_; }

  constexpr std::size_t block_size() const { return block_size_; }

  Cipher & operator << (const Input & input) {
    assert(nullptr != context_);
    assert(finished != mode_);
    if (!input.empty()) {
      std::size_t growth = std::ceil(static_cast<double>(input.size()) / block_size_);
      growth -= (output_.size() - written_) / block_size_;
      if (0 < growth) {
        output_.resize(output_.size() + growth * block_size_);
      }
      uint8_t * const destination = output_.data() + written_;
      int length = 0;
      int result_code = 0;
      switch (mode_) {
      case encrypt:
        result_code = EVP_EncryptUpdate(context_, destination, &length, input.data(), input.size());
        break;

      case decrypt:
        result_code = EVP_DecryptUpdate(context_, destination, &length, input.data(), input.size());
        break;

      default:
        assert(!"unrecheable");
        break;
      }
      assert(1 == result_code);
      written_ += length;
    }
    return *this;
  }

  Cipher & operator << (const char * const c_string) {
    std::vector<Input::value_type> buffer;
    std::copy(c_string, c_string + strlen(c_string), std::back_inserter(buffer));
    return operator << (buffer);
  }

  void operator >> (Output & output) {
    assert(nullptr != context_);
    assert(finished != mode_);
    const std::size_t growth = block_size_;
    output_.resize(output_.size() + growth);
    uint8_t * const destination = output_.data() + written_;
    int length = 0;
    int result_code = 0;
    switch (mode_) {
    case encrypt:
      result_code = EVP_EncryptFinal_ex(context_, destination, &length);
      break;

    case decrypt:
      result_code = EVP_DecryptFinal_ex(context_, destination, &length);
      break;

    default:
      assert(!"unrecheable");
      break;
    }
    assert(1 == result_code);
    written_ += length;

    mode_ = finished;
    output_.resize(written_);
    output.reserve(output.size() + written_);
    std::copy(output_.begin(), output_.end(), std::back_inserter(output));
  }
};

struct Key;

struct Point {
  EC_GROUP * group_ = nullptr;
  EC_POINT * point_ = nullptr;

  ~Point() {
    if (nullptr != point_) {
      EC_POINT_free(point_);
    }
    if (nullptr != group_) {
      EC_GROUP_clear_free(group_);
    }
  }

  Point(): group_(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)), point_(EC_POINT_new(group_)) {
    assert(nullptr != group_);
    assert(nullptr != point_);
  }

  Point(const Point &) = delete;
  Point(Point && other) :
    group_(std::move(other.group_)),
    point_(std::move(other.point_)) { }

  Point & operator = (const Point &) = delete;

  Point & operator = (Point && other) {
    std::swap(group_, other.group_);
    std::swap(point_, other.point_);
    return *this;
  }

  Point operator * (const BIGNUM * const factor) const {
    assert(nullptr != group_);
    assert(nullptr != point_);
    Point result;
    const int result_code = EC_POINT_mul(group_, result.point_, nullptr, point_, factor, nullptr);
    assert(1 == result_code);
    return result;
  }

  std::array<uint8_t, 0x20> x_array() const {
    assert(nullptr != group_);
    assert(nullptr != point_);
    BIGNUM * const x = BN_new();
    BIGNUM * const y = BN_new();
    {
      const int result_code = EC_POINT_get_affine_coordinates(group_, point_, x, y, nullptr);
      BN_free(y);
      assert(1 == result_code);
    }
    std::array<uint8_t, 0x20> result = { 0x0, };
    const auto bytes = BN_num_bytes(x);
    if (0x20 != bytes) {
      std::cout << "bytes " << bytes << std::endl;
      assert(0x20 == bytes);
    }
    {
      const int result_code = BN_bn2bin(x, result.data());
      assert(0x20 == result_code);
    }
    BN_free(x);
    return result;
  }

  friend class Key;
};

struct Key {
  BIGNUM * x_ = nullptr;
  BIGNUM * y_ = nullptr;
  BIGNUM * d_ = nullptr;
  EC_KEY * key_ = nullptr;

  ~Key() {
    if (nullptr != x_) {
      BN_free(x_);
    }
    if (nullptr != y_) {
      BN_free(y_);
    }
    if (nullptr != d_) {
      BN_free(d_);
    }
    assert(nullptr != key_);
    EC_KEY_free(key_);
  }

  Key() : key_(EC_KEY_new()) {
    assert(nullptr != key_);
  }

  Key(BIGNUM * const x, BIGNUM * const y, BIGNUM * const d) :
    x_(x), y_(y), d_(d), key_(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) { }

  Key(const Key &) = delete;

  Key(Key && other) :
    x_(std::move(other.x_)),
    y_(std::move(other.y_)),
    d_(std::move(other.d_)),
    key_(std::move(other.key_)) { }

  Key & operator = (const Key &) = delete;

  Key & operator = (Key && other) {
    std::swap(x_, other.x_);
    std::swap(y_, other.y_);
    std::swap(d_, other.d_);
    std::swap(key_, other.key_);
    return *this;
  }

  static Key make() {
    Key key;
    EC_GROUP * const group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    assert(nullptr != group);

    {
      const int result_code = EC_KEY_set_group(key.key_, group);
      assert(1 == result_code);
    }
    {
      const int result_code = EC_KEY_generate_key(key.key_);
      assert(1 == result_code);
    }
    key.d_ = BN_dup(EC_KEY_get0_private_key(key));
    assert(nullptr != key.d_);
    {
      const EC_POINT * const point = EC_KEY_get0_public_key(key);
      assert(nullptr != point);
      {
        key.x_ = BN_new();
        key.y_ = BN_new();
        const int result_code = EC_POINT_get_affine_coordinates(group, point, key.x_, key.y_, nullptr);
        assert(1 == result_code);
      }
    }
    EC_GROUP_clear_free(group);
    return key;
  }

  static Key make(const std::span<const uint8_t> & x, const std::span<const uint8_t> & y, const std::span<const uint8_t> & d = {}) {
    assert(0x20 <= x.size());
    BIGNUM * const big_x = BN_bin2bn(x.data(), 0x20, nullptr);
    assert(nullptr != big_x);
#if 0
    std::cout << "x = ";
    BN_print_fp(stdout, x);
    std::cout << std::endl;
#endif

    assert(0x20 <= y.size());
    BIGNUM * const big_y = BN_bin2bn(y.data(), 0x20, nullptr);
    assert(nullptr != big_y);
#if 0
    std::cout << "y = ";
    BN_print_fp(stdout, y);
    std::cout << std::endl;
#endif

    BIGNUM * big_d = nullptr;

    if (0x20 == d.size()) {
      big_d = BN_bin2bn(d.data(), 0x20, nullptr);
      assert(nullptr != big_d);
    }

#if 0
    std::cout << "d = ";
    BN_print_fp(stdout, big_d);
    std::cout << std::endl;
#endif

    Key key(big_x, big_y, big_d);

    {
      const int result_code = EC_KEY_set_public_key_affine_coordinates(key.key_, key.x_, key.y_);
      if (0 == result_code) {
        std::cerr << "Failed to set public key coordinates, error: "
          << ERR_peek_last_error() << " \""
          << ERR_error_string(ERR_peek_last_error(), nullptr)
          << "\"" << std::endl;
      }
    }

    if (nullptr != big_d) {
      const int result_code = EC_KEY_set_private_key(key.key_, key.d_);
      if (0 == result_code) {
        std::cerr << "Failed to set private key, error: "
          << ERR_peek_last_error() << " \""
          << ERR_error_string(ERR_peek_last_error(), nullptr)
          << "\"" << std::endl;
      }
    }

    return key;
  }

  operator EC_KEY * () const {
    return key_;
  }

  Point point() const {
    Point result;
    const int result_code = EC_POINT_set_affine_coordinates(result.group_, result.point_, BN_dup(x_), BN_dup(y_), nullptr);
    assert(1 == result_code);
    return result;
  }

  bool check() const {
    if (nullptr == key_) { return false; }
    const int result_code = EC_KEY_check_key(key_);
    if (0 == result_code) {
      std::cerr << "Key check failed , error: "
        << ERR_peek_last_error() << " \""
        << ERR_error_string(ERR_peek_last_error(), nullptr)
        << "\"" << std::endl;
    }
    return 1 == result_code;
  }

  int size() const {
    assert(nullptr != key_);
    return ECDSA_size(key_);
  }

  const BIGNUM * d() const {
    assert(nullptr != d_);
    return d_;
  }

  std::array<uint8_t, 0x20> x_array() const {
    assert(nullptr != x_);
    const auto bytes = BN_num_bytes(y_);
    if (0x20 != bytes) {
      std::cout << "bytes " << bytes << std::endl;
      assert(0x20 == bytes);
    }
    std::array<uint8_t, 0x20> result = { 0x0, };
    {
      const int result_code = BN_bn2bin(x_, result.data());
      assert(0x20 == result_code);
    }
    return result;
  }

  std::array<uint8_t, 0x20> y_array() const {
    assert(nullptr != y_);
    const auto bytes = BN_num_bytes(y_);
    if (0x20 != bytes) {
      std::cout << "bytes " << bytes << std::endl;
      assert(0x20 == bytes);
    }
    std::array<uint8_t, 0x20> result = { 0x0, };
    {
      const int result_code = BN_bn2bin(y_, result.data());
      assert(0x20 == result_code);
    }
    return result;
  }
};

struct Sha256 {
  using Digest = std::array<uint8_t, 0x20>;
  EVP_MD_CTX * context_ = nullptr;
  const EVP_MD * const algorithm_ = EVP_get_digestbyname("sha256");
  size_t counter_ = 0;
  ~Sha256() { if (nullptr != context_) { { EVP_MD_CTX_free(context_); context_ = nullptr; } } }
  Sha256() : context_(EVP_MD_CTX_new()) {
    EVP_DigestInit_ex2(context_, algorithm_, nullptr);
  }
  Sha256(Sha256 & o) : context_(EVP_MD_CTX_dup(o.context_)), counter_(o.counter_) { }
  Sha256(Sha256 && o) : context_(std::move(o.context_)), counter_(std::move(o.counter_)) { }
  Sha256 & operator = (const Sha256 & other) = delete;
  Sha256 & operator = (Sha256 && other) = delete;
  Sha256 & operator << (const std::span<const uint8_t> & message) {
    assert(nullptr != context_);
    const int result = EVP_DigestUpdate(context_, message.data(), message.size());
    assert(1 == result);
    counter_ += message.size();
    return *this;
  }
  Digest digest() {
    assert(nullptr != context_);
    Digest result = { '\0', };
    unsigned int length = 0;
    EVP_DigestFinal_ex(context_, result.data(), &length);
    assert(length == result.size());
    Sha256::~Sha256();
    return result;
  }
  size_t counter() const { return counter_; }
};

struct TLS {
  std::vector<uint8_t> certificate;
  Key public_key;
  Key private_key;
};

static const size_t DIGEST_SIZE = 0x20;

static bool sha256_hmac_compare(const std::span<const uint8_t> & key, const std::span<const uint8_t> & buffer, const std::span<const uint8_t, DIGEST_SIZE> & digest) {
  assert(!key.empty());
  assert(!buffer.empty());
  std::array<uint8_t, DIGEST_SIZE> out;
  {
    size_t length = 0;
    unsigned char * const result_code = EVP_Q_mac(
        /* OSSL_LIB_CTX *libctx = */ nullptr,
        /* const char *name = */ "HMAC",
        /* const char *propq = */ nullptr,
        /* const char *subalg = */ "SHA256",
        /* const OSSL_PARAM *params = */ nullptr,
        /* const void *key = */ key.data(),
        /* size_t keylen = */ key.size(),
        /* const unsigned char *data = */ buffer.data(),
        /* size_t datalen = */ buffer.size(),
        /* unsigned char *out = */ out.data(),
        /* size_t outsize = */ DIGEST_SIZE,
        /* size_t *outlen = */ &length);
    assert(DIGEST_SIZE == length);
    assert(out.data() == result_code);
  }

  return std::equal(digest.data(), digest.data() + DIGEST_SIZE, out.data(), out.data() + DIGEST_SIZE);
}

std::vector<uint8_t> prf(const std::span<const uint8_t> & key, const std::string & prefix, const std::span<const uint8_t> & original_seed, const uint16_t length) {

  std::vector<uint8_t> result;
  result.reserve(length + DIGEST_SIZE);
  std::vector<uint8_t> seed(DIGEST_SIZE + prefix.size() + original_seed.size());
  std::copy(prefix.begin(), prefix.end(), seed.begin() + DIGEST_SIZE);
  std::copy(original_seed.begin(), original_seed.end(), seed.begin() + DIGEST_SIZE + prefix.size());

  {
    size_t outlen = 0;
    unsigned char * const result_code = EVP_Q_mac(
      /* OSSL_LIB_CTX *libctx = */ nullptr,
      /* const char *name = */ "HMAC",
      /* const char *propq = */ nullptr,
      /* const char *subalg = */ "SHA256",
      /* const OSSL_PARAM *params = */ nullptr,
      /* const void *key = */ key.data(),
      /* size_t keylen = */ key.size(),
      /* const unsigned char *data = */ seed.data() + DIGEST_SIZE,
      /* size_t datalen = */ seed.size() - DIGEST_SIZE,
      /* unsigned char *out = */ seed.data(),
      /* size_t outsize = */ DIGEST_SIZE,
      /* size_t *outlen = */ &outlen);
    assert(DIGEST_SIZE == outlen);
    assert(nullptr != seed.data());
  }

  for (size_t total = 0; total < length; total += DIGEST_SIZE) {
    result.resize(total + DIGEST_SIZE);
    {
      size_t outlen = 0;
      unsigned char * const result_code = EVP_Q_mac(
          /* OSSL_LIB_CTX *libctx = */ nullptr,
          /* const char *name = */ "HMAC",
          /* const char *propq = */ nullptr,
          /* const char *subalg = */ "SHA256",
          /* const OSSL_PARAM *params = */ nullptr,
          /* const void *key = */ key.data(),
          /* size_t keylen = */ key.size(),
          /* const unsigned char *data = */ seed.data(),
          /* size_t datalen = */ seed.size(),
          /* unsigned char *out = */ result.data() + total,
          /* size_t outsize = */ DIGEST_SIZE,
          /* size_t *outlen = */ &outlen);
      assert(DIGEST_SIZE == outlen);
      assert(result.data() + total == result_code);
    }

    if (length <= total + DIGEST_SIZE) {
      break;
    }

    /* new seed prefix */
    {
      size_t outlen = 0;
      std::array<uint8_t, DIGEST_SIZE> digest{ 0x00, };
      unsigned char * const result_code = EVP_Q_mac(
          /* OSSL_LIB_CTX *libctx = */ nullptr,
          /* const char *name = */ "HMAC",
          /* const char *propq = */ nullptr,
          /* const char *subalg = */ "SHA256",
          /* const OSSL_PARAM *params = */ nullptr,
          /* const void *key = */ key.data(),
          /* size_t keylen = */ key.size(),
          /* const unsigned char *data = */ seed.data(),
          /* size_t datalen = */ DIGEST_SIZE,
          /* unsigned char *out = */ digest.data(),
          /* size_t outsize = */ DIGEST_SIZE,
          /* size_t *outlen = */ &outlen);
      assert(DIGEST_SIZE == outlen);
      assert(digest.data() == result_code);
      std::copy(digest.begin(), digest.end(), seed.begin());
    }
  }
  result.resize(length);
  return result;
}

struct HardwareKeys {
  static constexpr std::string product_name = "20HQS1QC00";
  static constexpr std::string serial_number = "PF17SPNU";

  static constexpr std::array<uint8_t, 0x20> password_hardcoded{
    0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a,
    0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19,
    0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38,
    0x38, 0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33,
  };
  
  static constexpr std::array<uint8_t, 0x20> gwk_sign_hardcoded{
    0x3a, 0x4c, 0x76, 0xb7, 0x6a, 0x97, 0x98, 0x1d,
    0x12, 0x74, 0x24, 0x7e, 0x16, 0x66, 0x10, 0xe7,
    0x7f, 0x4d, 0x9c, 0x9d, 0x07, 0xd3, 0xc7, 0x28,
    0xe5, 0x32, 0x91, 0x6b, 0xdd, 0x28, 0xb4, 0x54,
  };

  static std::vector<uint8_t> encryption_key() {
    std::vector<uint8_t> seed;
    seed.reserve(product_name.size() + serial_number.size() + 2);
    std::copy(product_name.begin(), product_name.end(), std::back_inserter(seed));
    seed.push_back('\0');
    std::copy(serial_number.begin(), serial_number.end(), std::back_inserter(seed));
    seed.push_back('\0');
    return prf(password_hardcoded, "GWK", seed, DIGEST_SIZE);
  }

  static auto validation_key() {
    return prf(HardwareKeys::encryption_key(), "GWK_SIGN", gwk_sign_hardcoded, 0x20);
  }
};

struct FlashParser {
  using Input = std::vector<uint8_t>;
  using Key = std::vector<uint8_t>;

  const Key psk_encryption_key_;
  const Key psk_validation_key_;

  FlashParser(Key && encryption_key, Key && validation_key) :
    psk_encryption_key_(std::move(encryption_key)),
    psk_validation_key_(std::move(validation_key)) { }

  struct Block {
    static constexpr uint8_t digest_size = 0x20;

    uint16_t id;
    const Input::const_iterator begin;
    uint16_t size;
    std::span<const Input::value_type> digest;
    std::span<const Input::value_type> body;

    bool check() const {
      std::vector<uint8_t> buffer(EVP_MAX_MD_SIZE);
      size_t length = 0;
      EVP_Q_digest(nullptr, "SHA256", nullptr, body.data(), body.size(), buffer.data(), &length);
      buffer.resize(length);
      assert(digest_size == length);
      return std::equal(buffer.data(), buffer.data() + digest_size, digest.data(), digest.data() + digest_size);
    }

    static Block parse(Input::const_iterator & iterator) {
      Block result{ .begin = iterator, };

      result.id = le16toh(
          *reinterpret_cast<const uint16_t*>(iterator.base()));
      iterator += 2;

      result.size = le16toh(
          *reinterpret_cast<const uint16_t*>(iterator.base()));
      iterator += 2;

      result.digest = std::span(iterator, digest_size);
      iterator += digest_size;
      result.body = std::span(iterator, result.size);
      iterator += result.size;

      return result;
    }
  };

  TLS operator () (const Input & input) {
    TLS result;
    auto iterator = input.cbegin();

    iterator += 2;
    const uint16_t blob_size = le16toh(*reinterpret_cast<const uint16_t*>(iterator.base()));
    iterator += 6;

    while (input.cend() > iterator) {
      Block block = Block::parse(iterator);

      if (0xffff == block.id) {
        break;
      }

      switch (block.id) {
      case 4: /* private key */
        parse_private_key(result, block);
        break;

      case 6: /* ecdh */
        parse_ecdh(result, block);
        break;

      case 3: /* certificate */
        parse_certificate(result, block);
        break;

      case 0: /* empty */
      case 1: /* empty */
      case 2: /* empty */
        parse_empty(result, block);
        break;

      default:
        break;
      }
    }

    return result;
  }

private:
  void parse_certificate(TLS & result, const Block & block) {
    result.certificate.reserve(block.size);
    std::copy(block.body.begin(), block.body.end(), std::back_inserter(result.certificate));
  }

  void parse_ecdh(TLS & result, const Block & block) {
    const std::vector<uint8_t> x{
      block.body.rbegin() + (block.size - 0x28),
      block.body.rbegin() + (block.size - 0x08)};

    const std::vector<uint8_t> y{
      block.body.rbegin() + (block.size - 0x6c),
      block.body.rbegin() + (block.size - 0x4c)}; 

    ::Key key = ::Key::make(x, y);
    assert(key.check());

    {
      const ::Key public_key = ::Key::make(
          std::vector<uint8_t>{
          0xf7, 0x27, 0x65, 0x3b, 0x4e, 0x16, 0xce, 0x06, 0x65, 0xa6,
          0x89, 0x4d, 0x7f, 0x3a, 0x30, 0xd7, 0xd0, 0xa0, 0xbe, 0x31,
          0x0d, 0x12, 0x92, 0xa7, 0x43, 0x67, 0x1f, 0xdf, 0x69, 0xf6,
          0xa8, 0xd3,},
          std::vector<uint8_t>{
          0xa8, 0x55, 0x38, 0xf8, 0xb6, 0xbe, 0xc5, 0x0d, 0x6e, 0xef,
          0x8b, 0xd5, 0xf4, 0xd0, 0x7a, 0x88, 0x62, 0x43, 0xc5, 0x8b,
          0x23, 0x93, 0x94, 0x8d, 0xf7, 0x61, 0xa8, 0x47, 0x21, 0xa6,
          0xca, 0x94,});

      assert(public_key.check());

      const uint16_t signature_length = le16toh(
          *reinterpret_cast<const uint16_t*>(block.body.data() + 0x90));

      std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);

      {
        size_t length = 0;
        EVP_Q_digest(nullptr, "SHA256", nullptr, block.body.data(), 0x90, digest.data(), &length);
        digest.resize(length);
      }

      const int code = ECDSA_verify(
          /*int type = */ 0,
          /*const unsigned char *dgst = */ digest.data(),
          /*int dgstlen = */ digest.size(),
          /*const unsigned char *sig = */ block.body.data() + 0x94,
          /*int siglen = */ signature_length,
          /*EC_KEY *ec_key = */ public_key);

      assert(1 == code);
    }

    result.public_key = std::move(key);
  }

  void parse_empty(TLS & result, const Block & block) {
    /* unimplemeted */
  }

  void parse_private_key(TLS & result, const Block & block) {
    const auto END = block.body.end();
    auto iterator = block.body.begin();

    if (2 != *iterator) {
      std::cerr << "Unknown private key prefix " << *iterator << std::endl;
    }

    ++iterator;
    assert(0x20 < END - iterator);

    const auto content = block.body.subspan(1, block.body.size() - 0x21);
    const std::span<const uint8_t, 0x20> digest(END - 0x20, END);
    assert(sha256_hmac_compare(psk_validation_key_, content, digest));

    const size_t AES256_BLOCK_SIZE = 16;
    const std::vector<uint8_t> iv(iterator, iterator + AES256_BLOCK_SIZE);
    iterator += AES256_BLOCK_SIZE;

    Cipher cipher(psk_encryption_key_, Cipher::decrypt, iv);
    Cipher::Output output;
    cipher << content >> output;

    output.erase(output.end() - output.back(), output.end()); // unpad (standard this time)
    std::reverse(output.begin(), output.end());

    const std::span<const uint8_t, DIGEST_SIZE> d(output.cbegin(), output.cbegin() + 0x20);
    const std::span<const uint8_t, DIGEST_SIZE> y(output.cbegin() + 0x20, output.cbegin() + 0x40);
    const std::span<const uint8_t, DIGEST_SIZE> x(output.cbegin() + 0x40, output.cbegin() + 0x60);

    result.private_key = ::Key::make(x, y, d);
    assert(result.private_key.check());
  } 
};

struct ValiditySensors {
  using Message = std::vector<uint8_t>;
  using Span = std::span<const uint8_t>;
  using Array = std::array<uint8_t, 0x20>;

  struct libusb_context * context_ = nullptr;
  struct libusb_device_handle * device_ = nullptr;

  bool secure_rx_ = false;
  bool secure_tx_ = false;

  Array host_random_ = { 0x00, };
  Array device_random_ = { 0x00, };

  Message device_session_id_;

  Sha256 handshake_hash_;
  TLS tls_;
  Key session_key_;
  std::vector<uint8_t> master_secret_;

  Message sign_key_;
  Message validation_key_;
  Message encryption_key_;
  Message decryption_key_;

  ~ValiditySensors() {
    if (nullptr != device_) {
      libusb_close(device_);
      device_ = nullptr;
    }

    if (nullptr != context_) {
      libusb_exit(context_);
      context_ = nullptr;
    }
  }

  ValiditySensors() = default;
  ValiditySensors(const ValiditySensors &) = delete;
  ValiditySensors & operator = (const ValiditySensors &) = delete;

  void init() {
    assert(nullptr == context_);
    const int result = libusb_init(&context_);
    if (0 > result) {
      context_ = nullptr;
      std::cerr << "libusb_init error " << result << std::endl;
    }
  }

  void find_device(const uint16_t vendor, const uint16_t product) {
    assert(nullptr != context_);
    assert(nullptr == device_);
    assert(0 != vendor);
    assert(0 != product);
    device_= libusb_open_device_with_vid_pid(context_, vendor, product);
    if (nullptr == device_) {
      std::cerr << "the device was not found" << std::endl;
    } else {
      libusb_reset_device(device_);
    }
  }

  void set_configuration() const {
    assert(nullptr != context_);
    assert(nullptr != device_);
    const int result = libusb_set_configuration(device_, 1);
    if (0 > result) {
      std::cerr << "libusb_set_configuration error " << result << std::endl;
    }
  }

  int send_bulk(const uint8_t endpoint, Message & vector, const unsigned int timeout = 0) const {
    assert(nullptr != context_);
    assert(nullptr != device_);
    assert(0 < endpoint);
    int transferred = 0;
    const int result = libusb_bulk_transfer(device_, endpoint, vector.data(), vector.size(), &transferred, timeout);
    if (0 > result) {
      std::cerr << "libusb_bulk_transfer error " << static_cast<libusb_error>(result) << std::endl;
    }
    vector.resize(transferred);
    return 0 == result ? transferred : result;
  }

  void setup_tls() {
    std::cout << "Retriving TLS Certificate..." << std::endl;
    {
      // Retrieves the TLS Cert from the device.
      Message vector{
        0x40, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00,
      };
      const int result = send_bulk(1, vector);
      assert(0 < result);
    }

    {
      ValiditySensors::Message response(4104);
      const int result = send_bulk(0x81, response, 3000);
      assert(0 < result);

      const auto encryption_key = HardwareKeys::encryption_key();
      const auto validation_key = HardwareKeys::validation_key();

      FlashParser parser(
        /* encryption_key = */ FlashParser::Key(encryption_key.begin(), encryption_key.end()),
        /* validation_key = */ FlashParser::Key(validation_key.begin(), validation_key.end()));

      tls_ = parser(response);
    }
  }

  void tls_handshake() {
    std::cout << "TLS handshake..." << std::endl;
    {
      const ValiditySensors::Message response = send_client_hello();
      parse_tls_response(response);
    }
    {
      const ValiditySensors::Message response = reply_client_hello();
      parse_tls_response(response);
    }
    std::cout << "TLS handshake has completed" << std::endl;
  }

  void send(Message message) {
    assert(secure_tx_);
    sign(0x17, message);
    Message message_encrypted{0x17, 0x03, 0x03, 0x00, 0x00, };
    const std::size_t size = encrypt(message, message_encrypted);
    message_encrypted[3] = size >> 8;
    message_encrypted[4] = size;
    {
      const int result = send_bulk(1, message_encrypted);
      assert(message_encrypted.size() == result);
    }
  }

private:
  Message send_client_hello() {
    {
      Message vector{0x44, 0x00, 0x00, 0x00, 0x16, 0x03, 0x03, 0x00};
      Message client_hello;
      make_client_hello(client_hello);
      vector.push_back(static_cast<uint8_t>(client_hello.size()));
      std::copy(client_hello.begin(), client_hello.end(), std::back_inserter(vector));
      {
        const int result = send_bulk(1, vector);
        assert(0 < result);
      }
    }
    Message output(128);
    {
      const int result = send_bulk(0x81, output, 3000);
      assert(0 < result);
    }
    return output;
  }

  Message reply_client_hello() {
    setup_session_keys();

    {
      Message message{0x44, 0x00, 0x00, 0x00,};

      {
        Message reply_client_hello;

        make_certificate(reply_client_hello);
        make_client_public_key(reply_client_hello);
        make_certificate_verify(reply_client_hello);

        { /* handshake */
          message.push_back(0x16);
          message.push_back(0x03);
          message.push_back(0x03);
          const size_t size = reply_client_hello.size();
          message.push_back(size >> 8);
          message.push_back(size);
        }

        std::copy(reply_client_hello.begin(), reply_client_hello.end(), std::back_inserter(message));
      }

      { /* make change cipher spec */
        message.push_back(0x14);
        message.push_back(0x03);
        message.push_back(0x03);
        message.push_back(0x00);
        message.push_back(0x01);
        message.push_back(0x01);
      }

      /* handshake */
      message.push_back(0x16);
      message.push_back(0x03);
      message.push_back(0x03);

      /* the next segment is already encrypted and signed */
      Message client_finish = make_finish();
      sign(0x16, client_finish);
      {
        Message::iterator iterator = message.insert(message.end(), 2, 0);
        const std::size_t size = encrypt(client_finish, message);
        *iterator = size >> 8;
        iterator += 1;
        *iterator = size;
      }
      const int result = send_bulk(1, message);
    }

    Message output(128);
    {
      const int result = send_bulk(0x81, output, 5000);
      assert(0 < result);
    }
    return output;
  }

  Message make_finish() {
    Message message;
    secure_tx_ = true;
    message.reserve(64);

    /* verify data prefix */
    message.push_back(0x14);

    /* verify data size */
    message.push_back(0x00);
    message.push_back(0x00);
    message.push_back(0x0c);

    { /* verify data */
      Sha256 hash = handshake_hash_;
      const Sha256::Digest seed = hash.digest();
      const std::vector<uint8_t> verify_data = prf(master_secret_, "client finished", seed, 0xC);
      std::copy(verify_data.begin(), verify_data.end(), std::back_inserter(message));
    }

    return message;
  }

  void parse_tls_response(const Message & message) {
    Message::const_iterator block = message.cbegin();
    const Message::const_iterator END = message.cend();
    while (END != block) {
      Message::const_iterator iterator = block;
      const uint8_t type = *reinterpret_cast<const uint8_t*>(iterator.base());
      iterator += 1;
      const uint8_t major = *reinterpret_cast<const uint8_t*>(iterator.base());
      iterator += 1;
      const uint8_t minor = *reinterpret_cast<const uint8_t*>(iterator.base());
      iterator += 1;
      const uint16_t size = be16toh(*reinterpret_cast<const uint16_t*>(iterator.base()));
      iterator += 2;
      if (3 != major || 3 != minor) {
        assert(!"Unexpected TLS version");
      }
      switch (type) {
        case 0x14:
          if (0x01 != *iterator) {
            std::cerr << "Unexpected ChangeCipherSpec payload" << std::endl;
          } else {
              assert(1 == size);
          }
          secure_rx_ = true;
          break;

        case 0x16:
          if (secure_rx_) {
            const Message handshake = decrypt(Span(iterator, iterator + size));
            assert(validate(0x16, handshake));
            handle_handshake(Span(handshake.begin(), handshake.end() - DIGEST_SIZE));
          } else {
            Span handshake(iterator, iterator + size);
            handshake_hash_ << handshake;
            handle_handshake(handshake);
          }
          break;

        case 0x17:
          /* handle app data */
          break;

        default:
          std::cerr << __func__ << " code 0x" << std::hex << static_cast<int>(type) << std::dec << std::endl; 
          assert(!"unimplemented");
          break;
      }
      block = iterator += size;
    }
  }

  void setup_session_keys() {
    session_key_ = Key::make();

    Point point = tls_.public_key.point();
    point = point * session_key_.d();

    std::array<uint8_t, 0x20> x = point.x_array();

    std::array<uint8_t, 0x40> seed{ 0x0, };
    std::copy(host_random_.begin(), host_random_.end(), seed.data());
    std::copy(device_random_.begin(), device_random_.end(), seed.data() + DIGEST_SIZE);

    master_secret_ = prf(x, "master secret", seed, 0x30);
    assert(0x30 == master_secret_.size());

    {
      std::vector<uint8_t> key_block = prf(master_secret_, "key expansion", seed, 0x120);
      sign_key_ = Message(key_block.begin(), key_block.begin() + 0x20);

      validation_key_ = Message(key_block.begin() + 0x20,
          key_block.begin() + 0x40);
      encryption_key_ = Message(key_block.begin() + 0x40,
          key_block.begin() + 0x60);
      decryption_key_ = Message(key_block.begin() + 0x60,
          key_block.begin() + 0x80);
    }
  }

  void make_certificate(Message & message) {
    assert(!tls_.certificate.empty());

    Message certificate;
    certificate.reserve(1024);
    certificate.push_back(0xb);
    certificate.push_back(0);
    certificate.push_back(0);
    certificate.push_back(0);

    for (int i = 0; 2 > i; ++i) {
      uint8_t length[2] = { 0x0, };
      *(reinterpret_cast<uint16_t*>(length)) = htobe16(tls_.certificate.size());
      certificate.push_back(0x0);
      certificate.push_back(length[0]);
      certificate.push_back(length[1]);
    }

    certificate.push_back(device_random_[4]);
    certificate.push_back(device_random_[5]);

    std::copy(tls_.certificate.begin(), tls_.certificate.end(), std::back_inserter(certificate));

    const size_t size = certificate.size() - 4;
    certificate[1] = size >> 16;
    certificate[2] = size >> 8;
    certificate[3] = size;

    handshake_hash_ << certificate;

    std::copy(certificate.begin(), certificate.end(), std::back_inserter(message));
  }

  void make_client_public_key(Message & message) {
    Message public_key;

    public_key.reserve(0x45);

    public_key.push_back(0x10);

    public_key.push_back(0);
    public_key.push_back(0);
    public_key.push_back(0x41);

    public_key.push_back(0x04);

    const std::array<uint8_t, 0x20> x = session_key_.x_array();
    std::copy(x.begin(), x.end(), std::back_inserter(public_key));

    const std::array<uint8_t, 0x20> y = session_key_.y_array();
    std::copy(y.begin(), y.end(), std::back_inserter(public_key));

    handshake_hash_ << public_key;

    std::copy(public_key.begin(), public_key.end(), std::back_inserter(message));
  }

  void make_certificate_verify(Message & message) {
    assert(tls_.private_key.check());
    Sha256 hash = handshake_hash_;
    const std::array<uint8_t, 0x20> digest = hash.digest();
    Message signature(4 + tls_.private_key.size());
    signature[0] = 0xf;
    {
      unsigned int signature_length = 0;
      const int result_code = ECDSA_sign(
        /*int type = */ 0,
        /*const unsigned char * = */ digest.data(),
        /*int dgstlen = */ digest.size(),
        /*unsigned char * = */ signature.data() + 4,
        /*unsigned int *siglen = */ &signature_length,
        /*EC_KEY *eckey = */ tls_.private_key);
      assert(1 == result_code);
      signature.resize(4 + signature_length);
    }
    const size_t size = signature.size() - 4;
    signature[1] = size >> 16;
    signature[2] = size >> 8;
    signature[3] = size;
    handshake_hash_ << signature;
    std::copy(signature.begin(), signature.end(), std::back_inserter(message));
  }

  void handle_handshake(const Span & handshake) {
    Span::iterator block = handshake.begin();
    const Span::iterator END = handshake.end();
    while (END != block) {
      Span::iterator iterator = block;
      
      const uint8_t type = *reinterpret_cast<const uint8_t*>(iterator.base());
      iterator += 1;
      const uint16_t l12 = be16toh(*reinterpret_cast<const uint16_t*>(iterator.base()));
      iterator += 2;
      const uint8_t l3 = *reinterpret_cast<const uint8_t*>(iterator.base());
      iterator += 1;
      const uint32_t length = (l12 << 8) | l3;
      switch (type) {
        case 0x02:
          handle_server_hello(Span(iterator, iterator + length));
          break;
        case 0x0d:
          handle_certificate_request(Span(iterator, iterator + length));
          break;
        case 0x0e:
          handle_server_hello_done(Span(iterator, iterator + length));
          break;
        case 0x14:
          handle_finish(Span(iterator, iterator + length));
          break;
        default:
          assert(!"unimplemented");
          break;
      }
      iterator += length;
      block = iterator;
    }
  }

  void handle_server_hello(const Span & server_hello) {
    Span::iterator iterator = server_hello.begin();
    const uint8_t major = *reinterpret_cast<const uint8_t*>(iterator.base());
    iterator += 1;
    const uint8_t minor = *reinterpret_cast<const uint8_t*>(iterator.base());
    iterator += 1;
    if (3 != major || 3 != minor) {
      assert(!"Unexpected TLS version");
    }

    std::copy(iterator, iterator + 0x20, device_random_.begin());
    iterator += 0x20;

    const uint8_t l = *reinterpret_cast<const uint8_t*>(iterator.base());
    iterator += 1;

    std::copy(iterator, iterator + l, std::back_inserter(device_session_id_));
    iterator += l;

    const uint16_t suite = be16toh(*reinterpret_cast<const uint16_t*>(iterator.base()));
    iterator += 2;

    assert(0xc005 == suite); // supported cipher
    assert(0x00 == *iterator); // compression should be disabled
  }

  void handle_certificate_request(const Span & certificate_request) {
    Span::iterator iterator = certificate_request.begin();
    const uint16_t algorithm = be16toh(*reinterpret_cast<const uint16_t*>(iterator.base()));
    iterator += 2;
    assert(0x0140 == algorithm); // supported sign and hash algorithm
    const uint16_t list = be16toh(*reinterpret_cast<const uint16_t*>(iterator.base()));
    iterator += 2;
    assert(0 == list); // empty list of certificate authorities
  }

  void handle_server_hello_done(const Span & server_hello_done) {
    assert(server_hello_done.empty());
  }

  void handle_finish(const Span & finish) {
    assert(!master_secret_.empty());
    std::array<uint8_t, DIGEST_SIZE> digest = handshake_hash_.digest();
    const Message verify_data = prf(master_secret_, "server finished", digest, 0x0C);
    assert(std::equal(finish.begin(), finish.end(), verify_data.begin(), verify_data.end()));
  }

  void make_client_hello(Message & buffer) {
    /* client_hello
     * 01
     * 00 00 41
     * 03 03
     * 2c14ead608eb8c352b0b114384fd372336f2d75c4f55f4ba89795d1fe58738e1
     * 07 00 00 00 00 00 00 00
     * 00 06 c0 05 00 3d 00 8d 
     * 00
     * 00 0a
     * 00 04 00 02 00 17
     * 00 0b 00 02 01 00
     **/
    buffer.push_back(0x01);

    buffer.push_back(0x00);
    buffer.push_back(0x00);
    buffer.push_back(0x3d);

    buffer.push_back(0x03);
    buffer.push_back(0x03);

    {
      const int code = RAND_bytes(host_random_.data(), host_random_.size());
      assert(1 == code);
      std::copy(host_random_.begin(), host_random_.end(), std::back_inserter(buffer));
    }

    /* session id */
    buffer.push_back(0x07);

    buffer.push_back(0x00); buffer.push_back(0x00);
    buffer.push_back(0x00); buffer.push_back(0x00);
    buffer.push_back(0x00); buffer.push_back(0x00);
    buffer.push_back(0x00);

    /* The next 6 bytes represent the cipher suites */
    buffer.push_back(0x00); buffer.push_back(0x02); 

    /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */
    buffer.push_back(0xc0); buffer.push_back(0x05);

    /* no compression options */
    buffer.push_back(0x00);

    /* extensions */
    buffer.push_back(0x00); buffer.push_back(0x0a);

    /* truncated hmac */
    buffer.push_back(0x00); buffer.push_back(0x04);
    buffer.push_back(0x00); buffer.push_back(0x02);
    buffer.push_back(0x00); buffer.push_back(0x17);

    /* EC points format = uncompressed */
    buffer.push_back(0x00); buffer.push_back(0x0b);
    buffer.push_back(0x00); buffer.push_back(0x02);
    buffer.push_back(0x01); buffer.push_back(0x00);

    handshake_hash_ << buffer;
  }

  void sign(const uint8_t type, Message & message) {
    assert(!sign_key_.empty());
    size_t size = message.size();
    std::vector<uint8_t> data;
    data.reserve(size + 5);
    data.push_back(type);
    data.push_back(0x03);
    data.push_back(0x03);
    data.push_back(message.size() >> 8);
    data.push_back(message.size());
    std::copy(message.begin(), message.end(), std::back_inserter(data));
    message.resize(size + DIGEST_SIZE);
    {
      size_t outlen = 0;
      unsigned char * const result_code = EVP_Q_mac(
          /* OSSL_LIB_CTX *libctx = */ nullptr,
          /* const char *name = */ "HMAC",
          /* const char *propq = */ nullptr,
          /* const char *subalg = */ "SHA256",
          /* const OSSL_PARAM *params = */ nullptr,
          /* const void *key = */ sign_key_.data(),
          /* size_t keylen = */ sign_key_.size(),
          /* const unsigned char *data = */ data.data(),
          /* size_t datalen = */ data.size(),
          /* unsigned char *out = */ message.data() + size,
          /* size_t outsize = */ DIGEST_SIZE,
          /* size_t *outlen = */ &outlen);
      assert(message.data() + size == result_code);
      assert(DIGEST_SIZE == outlen);
    }
  }

  bool validate(const uint8_t type, const Message & message) {
    assert(!validation_key_.empty());
    assert(DIGEST_SIZE < message.size());
    size_t size = message.size() - DIGEST_SIZE;
    Message data;
    data.reserve(size + 5);
    data.push_back(type);
    data.push_back(0x03);
    data.push_back(0x03);
    data.push_back(size >> 8);
    data.push_back(size);
    std::copy(message.begin(), message.begin() + size, std::back_inserter(data));
    const std::span<const uint8_t, DIGEST_SIZE> digest(message.begin() + size, message.end());
    return sha256_hmac_compare(validation_key_, data, digest);
  }

  std::size_t encrypt(Message in, Message & out) {
    assert(!encryption_key_.empty());
    const std::size_t out_original_size = out.size();
    Cipher encryption(encryption_key_, Cipher::encrypt);
    const std::span<const uint8_t> iv = encryption.iv();
    Cipher decryption(encryption_key_, Cipher::decrypt, iv);
    out.reserve(out.size() + in.size() + 0x10);
    std::copy(iv.begin(), iv.end(), std::back_inserter(out));
    pad(in);
    encryption << in >> out;
    assert(out.size() > out_original_size);
    {
      std::vector<uint8_t> n;
      decryption << Cipher::Input(out.begin() + out_original_size + iv.size(), out.end()) >> n;
      assert(std::equal(in.begin(), in.end(), n.begin(), n.end()));
    }
    return out.size() - out_original_size;
  }

  Message decrypt(const std::span<const uint8_t> & in) {
    assert(!decryption_key_.empty());
    assert(0x10 < in.size());

    std::vector<uint8_t> iv(in.begin(), in.begin() + 0x10);
    std::vector<uint8_t> result;
    result.reserve(in.size() - 0x10);
    const std::span<const uint8_t> encrypted_body(in.begin() + 0x10, in.end());

    {
      Cipher cipher(decryption_key_, Cipher::decrypt, iv);
      cipher << encrypted_body >> result;
    }

    {
      std::vector<uint8_t> n = iv;
      n.reserve(in.size());
      Cipher cipher(decryption_key_, Cipher::encrypt, iv);
      cipher << result >> n;
      assert(std::equal(in.begin(), in.end(), n.begin(), n.end()));
    }

    unpad(result);
    return result;
  }

  void pad(Message & message) {
    const uint8_t remaining = 16 - (message.size() % 16);
    message.insert(message.end(), remaining, remaining - 1);
  }

  void unpad(Message & message) {
    const uint8_t pad = message.back() + 1;
    assert(16 >= pad);
    message.erase(message.end() - pad, message.end());
  }

};

int main() {
  ValiditySensors sensors;

  // should collapse these two methods together ?
  sensors.init();
  sensors.find_device(0x138A, 0x0097);
  sensors.set_configuration();

  {
    {
      ValiditySensors::Message vector{ 0x01, };
      const int result = sensors.send_bulk(1, vector);
      assert(0 < result);
    }

    {
      ValiditySensors::Message vector(1024);
      const int result = sensors.send_bulk(0x81, vector, 3000);
      assert(0 < result);
    }
  }

  /* ------------------------------------------------------------ */

  {
    {
      ValiditySensors::Message vector{ 0x19, };
      const int result = sensors.send_bulk(1, vector);
      assert(0 < result);
    }

    {
      ValiditySensors::Message vector(1024);
      const int result = sensors.send_bulk(0x81, vector, 3000);
      assert(0 < result);
    }
  }

  /* ------------------------------------------------------------ */

  {
    {
      ValiditySensors::Message vector{ 0x43, 0x02, };
      const int result = sensors.send_bulk(1, vector);
      assert(0 < result);
    }

    {
      ValiditySensors::Message vector(1024);
      const int result = sensors.send_bulk(0x81, vector, 3000);
      assert(0 < result);
    }
  }

  /* ------------------------------------------------------------ */

  {
    {
      ValiditySensors::Message vector{
        0x06, 0x02, 0x00, 0x00, 0x01, 0x5c, 0xb5, 0x60, 0xaf, 0xa5,
        0x95, 0xd0, 0xdc, 0xf4, 0xfc, 0xa0, 0x9e, 0xbb, 0x69, 0x30,
        0x1e, 0x2b, 0x9e, 0x24, 0xa5, 0xdf, 0xb6, 0xf2, 0x60, 0x28,
        0x33, 0x42, 0x7d, 0x3b, 0xd6, 0x52, 0x22, 0xc4, 0x18, 0xff,
        0x15, 0xb5, 0x45, 0x87, 0xab, 0x28, 0x54, 0xc4, 0xfe, 0x9a,
        0xea, 0x74, 0xfa, 0x55, 0x56, 0x72, 0x03, 0x6f, 0xa3, 0xec,
        0x73, 0xc6, 0x91, 0x2c, 0x58, 0xb1, 0xb4, 0x9c, 0xbd, 0xcc,
        0x76, 0x64, 0x16, 0x54, 0x82, 0xcd, 0x70, 0xd5, 0xbb, 0x95,
        0xd9, 0xd4, 0x69, 0x62, 0x6f, 0xdc, 0x2e, 0x01, 0x2d, 0x74,
        0x15, 0x7c, 0x57, 0x92, 0x26, 0x09, 0x68, 0xa2, 0xa4, 0x57,
        0x2b, 0x1c, 0xcc, 0xcc, 0x26, 0xec, 0x2e, 0x2e, 0xd0, 0xdd,
        0xda, 0x1b, 0x09, 0x31, 0xd3, 0xd0, 0x56, 0x64, 0x60, 0x91,
        0x5d, 0x43, 0xe0, 0xa6, 0x54, 0xa0, 0x58, 0x27, 0x06, 0xbe,
        0x91, 0x13, 0xea, 0x88, 0xf0, 0xc1, 0x5b, 0xa0, 0x58, 0x50,
        0x4d, 0xdd, 0xf0, 0x50, 0xb6, 0xe8, 0xd4, 0xeb, 0xb3, 0x4e,
        0xbb, 0xa3, 0x3e, 0x86, 0x51, 0xc7, 0x5e, 0x5f, 0xb2, 0x8f,
        0x85, 0xc8, 0x31, 0x97, 0xdf, 0x1d, 0xe4, 0x60, 0xd9, 0xe1,
        0xcb, 0x82, 0x20, 0x87, 0x53, 0xce, 0xff, 0x0e, 0xf6, 0x0a,
        0x82, 0x3d, 0xba, 0x75, 0xd0, 0x55, 0x48, 0xf5, 0xb3, 0xa5,
        0xa0, 0xe2, 0x97, 0x22, 0x32, 0xf7, 0x40, 0x3b, 0xd6, 0x86,
        0x9d, 0xa9, 0x0e, 0x53, 0x71, 0xa0, 0xab, 0x8a, 0xd2, 0x39,
        0x72, 0xf1, 0x59, 0x76, 0x30, 0xf5, 0xff, 0x7c, 0x8b, 0x82,
        0x72, 0x80, 0x05, 0x63, 0x47, 0x72, 0x88, 0xb5, 0x59, 0x1b,
        0xbb, 0x03, 0x41, 0xd3, 0x97, 0x5e, 0xfc, 0x17, 0x78, 0x22,
        0x57, 0x67, 0xfa, 0x35, 0x48, 0x0f, 0xf7, 0xf8, 0xdd, 0x63,
        0x3e, 0x40, 0x34, 0xac, 0x32, 0xe4, 0xaf, 0x58, 0xb8, 0x6e,
        0xbc, 0x63, 0x55, 0x2c, 0xb3, 0x5b, 0x12, 0xb2, 0x85, 0x25,
        0x5d, 0xea, 0xf3, 0xa3, 0x2b, 0xf4, 0x6c, 0xdc, 0x5a, 0xd3,
        0xbc, 0x1c, 0x9e, 0xd1, 0xbc, 0xc1, 0x12, 0xc7, 0x21, 0x43,
        0xf9, 0xae, 0xc5, 0x68, 0xe2, 0xca, 0xcf, 0xa8, 0x9b, 0xa0,
        0xc7, 0xbb, 0x65, 0x59, 0x0d, 0x8b, 0x93, 0xe6, 0x87, 0x1a,
        0x33, 0xc6, 0xc6, 0x98, 0x3c, 0x0a, 0xcd, 0x04, 0xe7, 0x37,
        0xff, 0x55, 0xee, 0xe0, 0x24, 0xca, 0x6b, 0x9a, 0x48, 0x33,
        0x2c, 0x1a, 0x69, 0xa5, 0xa3, 0xfd, 0xd2, 0x4b, 0x96, 0x4c,
        0xf7, 0xe7, 0xc5, 0x52, 0x29, 0xbb, 0x0b, 0x48, 0xa6, 0xe3,
        0x39, 0xeb, 0x2c, 0x42, 0xd0, 0x7e, 0xc8, 0x50, 0xa4, 0xee,
        0x78, 0x06, 0x60, 0xad, 0x6c, 0x77, 0xff, 0xa3, 0x02, 0xa6,
        0x3b, 0xd1, 0x94, 0x26, 0x13, 0x4c, 0x45, 0x33, 0xd6, 0x91,
        0x92, 0xef, 0x2e, 0x16, 0x59, 0x1d, 0xf2, 0x63, 0x94, 0x79,
        0x1a, 0x4e, 0xcb, 0x99, 0x4a, 0x24, 0xf5, 0xa7, 0xf7, 0x0f,
        0x1e, 0xb2, 0x60, 0x4e, 0x6b, 0xfb, 0x67, 0xa4, 0x52, 0xcb,
        0x74, 0xea, 0xd8, 0xb0, 0xd9, 0x80, 0x8f, 0x89, 0x0a, 0xc3,
        0x86, 0x75, 0x0c, 0xba, 0xc0, 0x6e, 0xe0, 0x3a, 0x85, 0x21,
        0x45, 0x09, 0x40, 0x53, 0xb2, 0xb0, 0x74, 0xb9, 0x90, 0x5d,
        0xe5, 0xcd, 0xbf, 0x22, 0x72, 0xb6, 0x7e, 0x51, 0xf1, 0x59,
        0x16, 0x47, 0x78, 0xd6, 0xd2, 0xef, 0x7a, 0x1c, 0xcb, 0x81,
        0xdf, 0x9f, 0x89, 0x6d, 0xdb, 0x38, 0xce, 0x11, 0xe8, 0x14,
        0x0c, 0xf6, 0xcb, 0x9c, 0x82,
      };
      const int result = sensors.send_bulk(1, vector);
      assert(0 < result);
    }

    {
      ValiditySensors::Message vector(1024);
      const int result = sensors.send_bulk(0x81, vector, 3000);
      assert(0 < result);
    }
  }

  /* ------------------------------------------------------------ */

  sensors.setup_tls();
  sensors.tls_handshake();

  /* ------------------------------------------------------------ */

  std::cout << "led" << std::endl;

  {
    ValiditySensors::Message vector{
      0x39, 0xff, 0x10, 0x00, 0x00, 0xff, 0x03, 0x00, 0x00, 0x01,
      0xff, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
      0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0x03, 0x00, 0x00, 0x01,
      0xff, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0x03, 0x00, 0x00, 0x01,
      0xff, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00,
    };
    sensors.send(vector);
  }

  /* ------------------------------------------------------------ */

  return 0;
}
