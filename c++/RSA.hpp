#ifndef RSA_HPP_
#define RSA_HPP_

#include <NTL/ZZ.h>
#include <tuple>

class RSAKey{
private:
  NTL::ZZ p, q, n, e, d;
public:
  void make(const unsigned int& length);

  void set_public_key(const std::tuple<NTL::ZZ, NTL::ZZ>& public_key);
  std::tuple<NTL::ZZ, NTL::ZZ> get_public_key();
  std::tuple<NTL::ZZ, NTL::ZZ, NTL::ZZ> get_private_key();
};

class RSA{
private:
  NTL::ZZ chineseRemainderTheorem(const NTL::ZZ& m, const NTL::ZZ& d, const NTL::ZZ& p, const NTL::ZZ& q);
  unsigned char* rsa(unsigned char in[], unsigned int inLen, unsigned int& outLen, const NTL::ZZ& max_block_length,
                     const NTL::ZZ& k_slot1, const NTL::ZZ& k_slot2, const NTL::ZZ& k_slot3);
public:
  unsigned char* encrypt(unsigned char in[], unsigned int inLen, unsigned int& outLen, const std::tuple<NTL::ZZ, NTL::ZZ>& public_key);
  unsigned char* decrypt(unsigned char in[], unsigned int inLen, unsigned int& outLen, const std::tuple<NTL::ZZ, NTL::ZZ, NTL::ZZ>& private_key);
};

#endif
