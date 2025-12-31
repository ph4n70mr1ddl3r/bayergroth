#include <gmpxx.h>
#include <iostream>

int main() {
    mpz_class a("12345678901234567890");
    mpz_class p("1000000007");
    
    std::cout << "a = " << a << std::endl;
    std::cout << "p = " << p << std::endl;
    
    mpz_class inv;
    mpz_invert(inv.get_mpz_t(), a.get_mpz_t(), p.get_mpz_t());
    std::cout << "inv(a) mod p = " << inv << std::endl;
    
    mpz_class result = a * inv % p;
    std::cout << "a * inv(a) mod p = " << result << std::endl;
    
    return 0;
}
