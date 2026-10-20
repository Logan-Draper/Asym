using System.Numerics;
using System.Security.Cryptography;

namespace MathUtils;

/// <summary>
/// Utility methods for working with primes.
/// </summary>
public static class PrimeUtils {

    /// <summary>
    /// Get a random prime number.
    /// </summary>
    /// <param name="bits">Number of bits in the prime number.</param>
    /// <returns>Prime number on the given number of bits.</returns>
    
    public static BigInteger GetRandomPrime(int bits) {
        if(bits <= 2){
            throw new ArgumentOutOfRangeException();
        }
       //Integer way of determining the number of bytes i needed to allocate for to randomize later.
       int num_bytes = ((bits+7)/8);
     byte[] byte_stream = new byte[num_bytes];
    BigInteger prime;
    do {
        RandomNumberGenerator.Fill(byte_stream);
        //This makes sure that the bottom bit is set to 1, this rules out literally half the possible cases where its even. Makes it a lot faster.
        byte_stream[0] |= 0x01;
        //Had to call the specific constructor because BigInteger is naturally Signed, but in this case i want it to be unsigned explicitly.
        prime = new BigInteger(byte_stream, isUnsigned: true);
        //While its not a prime based on miller rabin, we loop.
    } while (!IsProbablePrime(prime));
    return prime;
} 

    /// <summary>
    /// Tests whether a number is probably prime using the Miller-Rabin primality test.
    /// </summary>
    /// <param name="n">The number to test (must be greater than 1).</param>
    /// <param name="rounds">
    /// The number of witness rounds. Higher values reduce the probability of a false
    /// positive. 40 rounds gives a false positive probability of at most 2^(-80).
    /// </param>
    /// <returns>
    /// False if n is definitely composite; true if n is probably prime.
    /// </returns>
    public static bool IsProbablePrime(BigInteger n, int rounds = 40) {
        if(n == 2 || n == 3){
            return true;
        }
        if(n < 2 || n % 2 == 0){
            return false;
        }
        //This section will give me the number of times n-1 can be divided by two, which is the limit of times I need to check the witnesses values.
        int remainder = 0;
        BigInteger d = n -1;
        while(d % 2 == 0){
            d = d/2;
            remainder+=1;
        }

        for(int i = 0; i < rounds;i++){
            BigInteger witness = RandomBigInteger(2,n-2);
            BigInteger test_val = BigIntegerExtensions.ModExp(witness,d,n);
            if(test_val == 1 || test_val == n-1){
                continue;
            }else{
                bool not_prime = true;
                //Inner loop i do the 2^n times to check the amount of witnesses.
                for(int j = 0; j < remainder-1;j++){
                    //Exponentiate
                    test_val = BigIntegerExtensions.ModExp(test_val,2,n);
                    if(test_val == n-1){
                        not_prime = false;
                        break;
                    }
                }
            if(not_prime){
                return false;
                }
            } 
        }
        return true;
           }
        //I ripped a fair amount of the components of this from the RandomPrime function, its a lot of the same 
        // but I had to use it partially here so that I could get a random witness in the Probably Prime function.
public static BigInteger RandomBigInteger(BigInteger min, BigInteger max) {
        if (min > max) {
            throw new ArgumentOutOfRangeException();
        }
 
        BigInteger range = max - min;
 
        byte[] rangeBytes = range.ToByteArray();
        int num_bytes = rangeBytes.Length + 1;
        byte[] byte_stream = new byte[num_bytes];
 
        BigInteger result;
        do {
            RandomNumberGenerator.Fill(byte_stream);
            byte_stream[num_bytes - 1] = 0;
            result = new BigInteger(byte_stream);
        } while (result > range);
 
        return min + result;
    }
} 