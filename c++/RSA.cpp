#include "RSA.hpp"
#include <iostream>
#include <stdio.h>
#include <vector>

NTL::ZZ inv_mod(NTL::ZZ n1, NTL::ZZ n2){
  NTL::ZZ x1 = NTL::ZZ(0), x2 = NTL::ZZ(1), y1 = x1, y2 = x2;
  NTL::ZZ q, x, y, z, inverse = NTL::ZZ(1), sav = n2;
  if (n2 != 0) {
    while (n2 > 0) {
      q = n1 / n2;
      x = n1; y = x2; z = y2;
      n1 = n2; n2 = x - q * n2;
      x2 = x1; x1 = y - q * x1;
      y2 = y1; y1 = z - q * y1;
      if (n2 == 1) {
        inverse = x1;
        if (inverse < 1)
          inverse += sav;
      }
    }
  }
  return inverse;
}

void RSAKey::make(const unsigned int& length){
  NTL::GenPrime(p, length);
  do{
    NTL::GenPrime(q, length);
  }while(p == q);
  n = p * q;
  NTL::ZZ y_n = (p - 1) * (q - 1);
  do{
    e = NTL::RandomBits_ZZ(length) % y_n + 2;
  }while(NTL::GCD(e, y_n) != 1);
  d = inv_mod(e, y_n);
  /*std::cout << p << ' ' << q << '\n';
  std::cout << n << ' ' << y_n <<'\n';
  std::cout << d << ' ' << e <<'\n';*/
}

void RSAKey::set_public_key(const std::tuple<NTL::ZZ, NTL::ZZ>& public_key){
  e = std::get<0>(public_key);
  n = std::get<1>(public_key);
}

std::tuple<NTL::ZZ, NTL::ZZ> RSAKey::get_public_key(){
  return {e, n};
}

std::tuple<NTL::ZZ, NTL::ZZ, NTL::ZZ> RSAKey::get_private_key(){
  return {d, p, q};
}

NTL::ZZ mod_pow(NTL::ZZ b, NTL::ZZ e, NTL::ZZ m) {
  NTL::ZZ mod_p = NTL::ZZ(1);
  while (e > 0) {
    if ((e & 1) > 0) mod_p = (mod_p * b) % m;
    e >>= 1;
    b = (b * b) % m;
  }
  return mod_p;
}

NTL::ZZ mod(NTL::ZZ num, NTL::ZZ mod) {
  NTL::ZZ num_div_mod = num / mod;
  NTL::ZZ r = (num < 0) ? (num - (num_div_mod - 1) * mod) : num - num_div_mod * mod;
  return r;
}

NTL::ZZ RSA::chineseRemainderTheorem(const NTL::ZZ& m, const NTL::ZZ& d, const NTL::ZZ& p, const NTL::ZZ& q){
  NTL::ZZ m1 = mod_pow(m, mod(d, p - 1), p);
  NTL::ZZ m2 = mod_pow(m, mod(d, q - 1), q);
  NTL::ZZ h = mod(inv_mod(q, p) * (m1 - m2), p);
  return mod(m2 + (h * q), p * q);
}

unsigned char* RSA::rsa(unsigned char in[], unsigned int inLen, unsigned int& outLen, const NTL::ZZ& max_block_length,
                        const NTL::ZZ& k_slot1, const NTL::ZZ& k_slot2, const NTL::ZZ& k_slot3){
  NTL::ZZ block = NTL::ZZ(0), temp_block;
  std::vector<unsigned char> out_buf;

  for(unsigned int i = 0; i < inLen + 1; ++i){
    temp_block = block;
    if(i < inLen){
      block <<= 8;
      block |= in[i];
    }
    if(block >= max_block_length || i == inLen){
      NTL::ZZ c;
      if(k_slot2 == -1)
        c = mod_pow(temp_block, k_slot1, max_block_length);
      else
        c = chineseRemainderTheorem(temp_block, k_slot1, k_slot2, k_slot3);

      unsigned int n_c_bits = NTL::NumBits(c);
      unsigned int n_full_bytes = n_c_bits / 8;
      unsigned int n_remainder_bits = n_c_bits % 8;

      out_buf.reserve(n_full_bytes + (n_remainder_bits != 0));
      out_buf.push_back(NTL::to_int((c >> (n_c_bits - n_remainder_bits)) & 0xff));

      for (unsigned int j = n_full_bytes; j > 0; --j)
        out_buf.push_back(NTL::to_int((c >> ((j - 1) * 8)) & 0xff));
      block &= 0xff;
    }
  }

  outLen = out_buf.size();
  unsigned char* out = new unsigned char[outLen];
  memcpy(out, out_buf.data(), outLen);
  return out;
}

unsigned char* RSA::encrypt(unsigned char in[], unsigned int inLen, unsigned int& outLen, const std::tuple<NTL::ZZ, NTL::ZZ>& public_key){
  NTL::ZZ max_block_length = std::get<1>(public_key);
  return rsa(in, inLen, outLen, max_block_length, std::get<0>(public_key), NTL::ZZ(-1), NTL::ZZ(-1));
}

unsigned char* RSA::decrypt(unsigned char in[], unsigned int inLen, unsigned int& outLen, const std::tuple<NTL::ZZ, NTL::ZZ, NTL::ZZ>& private_key){
  NTL::ZZ max_block_length = std::get<1>(private_key) * std::get<2>(private_key);
  return rsa(in, inLen, outLen, max_block_length, std::get<0>(private_key), std::get<1>(private_key), std::get<2>(private_key));
}
