#include <gmpxx.h>
#include <iostream>

int main() {
    mpz_class p("3877067762158797083");
    mpz_class q("1938533881079398541");
    mpz_class g("2");
    mpz_class rho("1390286466654396628");
    mpz_class outputRand("1402999176770520471");
    mpz_class z1("854751762345518558");
    
    // Compute rho + outputRand mod q
    mpz_class sum = rho + outputRand;
    sum %= q;
    if (sum < 0) sum += q;
    std::cout << "(rho + outputRand) mod q = " << sum << std::endl;
    std::cout << "z1 = " << z1 << std::endl;
    std::cout << "Match: " << (sum == z1 ? "YES" : "NO") << std::endl;
    
    // Compute g^z1
    mpz_class g_z1;
    mpz_powm(g_z1.get_mpz_t(), g.get_mpz_t(), z1.get_mpz_t(), p.get_mpz_t());
    std::cout << "g^z1 = " << g_z1 << std::endl;
    
    // Compute g^(rho + outputRand) = g^rho * g^outputRand
    mpz_class g_rho, g_outputRand, g_sum;
    mpz_powm(g_rho.get_mpz_t(), g.get_mpz_t(), rho.get_mpz_t(), p.get_mpz_t());
    mpz_powm(g_outputRand.get_mpz_t(), g.get_mpz_t(), outputRand.get_mpz_t(), p.get_mpz_t());
    g_sum = (g_rho * g_outputRand) % p;
    std::cout << "g^(rho+outputRand) = " << g_sum << std::endl;
    
    // Compute g^(sum mod q) - should equal g^sum if q divides the exponent difference
    mpz_class sum_mod_q = (rho + outputRand) % q;
    mpz_class g_sum_mod_q;
    mpz_powm(g_sum_mod_q.get_mpz_t(), g.get_mpz_t(), sum_mod_q.get_mpz_t(), p.get_mpz_t());
    std::cout << "g^((rho+outputRand) mod q) = " << g_sum_mod_q << std::endl;
    
    // Check if g^(rho+outputRand) == g^((rho+outputRand) mod q)
    // This is only true if g^q = 1 (which it should be for our generator!)
    mpz_class g_q;
    mpz_powm(g_q.get_mpz_t(), g.get_mpz_t(), q.get_mpz_t(), p.get_mpz_t());
    std::cout << "g^q = " << g_q << std::endl;
    std::cout << "This should be 1 for a valid generator of order-q subgroup" << std::endl;
    
    // So g^(rho+outputRand) = g^((rho+outputRand) mod q) only if g^q = 1
    std::cout << "g^z1 == g^(rho+outputRand): " << (g_z1 == g_sum ? "YES" : "NO") << std::endl;
    
    return 0;
}
