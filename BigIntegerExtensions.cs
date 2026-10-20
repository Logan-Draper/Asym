using System.Numerics;

namespace MathUtils;

public static class BigIntegerExtensions {

    /// <summary>
    /// Computes the Greatest Common Divisor of a and b, along with the 
    /// Bézout coefficients u and v such that: (a * u) + (b * v) = gcd(a, b).
    /// </summary>
    /// <param name="a">First inteer.</param>
    /// <param name="b">Second integer.</param>
    /// <returns>A tuple (gcd, x, y), where gcd is the GCD of a and b,
    /// and x, y are the Bézout coefficients.</returns>
    /// <remarks>
    /// Your implementation will need to handle the case that gcd(a, 0) = gcd(0, a) = a.
    /// </remarks>
    /// 
    /// 
    /// I am a little worried about the massive explosion that recursive calls could make here. But iteration feels less intuitive than
    /// the idea of the base case that was discussed in class. I hope this gets full points?
    public static (BigInteger gcd, BigInteger u, BigInteger v) ExtendedEuclidean(BigInteger a, BigInteger b) {
        BigInteger u,v,gcd;
        if(b == 0){
            u = 1;
            v = 0;
            return (a,u,v);
        }else{
        (gcd,u,v) = ExtendedEuclidean(b,a%b);
        BigInteger curr_quotient = a/b;
        BigInteger x = v;
        BigInteger y = u - curr_quotient * v;
        return (gcd,x,y);
    }
    }

    extension(BigInteger a) {

        /// <summary>
        /// Calculates this (mod n).
        /// </summary>
        /// <param name="n">The modulus n.</param>
        /// <returns>this (mod n)/returns>
        public BigInteger Mod(BigInteger n) {
            if (n < 2) throw new ArgumentOutOfRangeException(nameof(n), "Modulus must be greater than 1.");

            var result = a % n;
            if (result < 0) return result + n;
            return result;
        }
    
        /// <summary>
        /// Calculates this + b (mod n).
        /// </summary>
        /// <param name="b">The number to add.</param>
        /// <param name="n">The modulus n.</param>
        /// <returns>this + b (mod n)/returns>
        public BigInteger ModAdd(BigInteger b, BigInteger n) {
            return Mod(Mod(a, n) + Mod(b, n), n);
        }

        /// <summary>
        /// Calculates this - b (mod n).
        /// </summary>
        /// <param name="b">The number to subtract.</param>
        /// <param name="n">The modulus n.</param>
        /// <returns>this - b (mod n)/returns>
        public BigInteger ModSubstract(BigInteger b, BigInteger n) {
            return Mod(Mod(a, n) + Mod(-b, n), n);
        }

        /// <summary>
        /// Calculates this * b (mod n).
        /// </summary>
        /// <param name="b">The number to multiply.</param>
        /// <param name="n">The modulus n.</param>
        /// <returns>this * b (mod n)/returns>
        public BigInteger ModMultiply(BigInteger b, BigInteger n) {
            return Mod(Mod(a, n) * Mod(b, n), n);
        }

        /// <summary>
        /// Calculates this^-1 (mod n).
        /// </summary>
        /// <param name="n">The modulus n.</param>
        /// <returns>this^-1 (mod n)/returns>
        /// <remarks>
        /// You must implement this using <see cref="ExtendedEuclidean"/>.
        /// </remarks>
        public BigInteger ModInverse(BigInteger n) {
         //Definition of having a modular inverse is that n and a are relatively prime and their GCD returns 1.
         (BigInteger gcd, BigInteger u, BigInteger v) = ExtendedEuclidean(a,n);
         if(gcd == 1){
         return u.Mod(n);
         }
        else{
        throw new ArgumentException("GCD wasn't 1 gang they aren't relatively prime.\n");
        }
         }

        /// <summary>
        /// Calculates this / b (mod n).
        /// </summary>
        /// <param name="b">The number to divide by.</param>
        /// <param name="n">The modulus n.</param>
        /// <returns>this / b (mod n)/returns>
        /// Not sure about potential edge cases on this. But I think its that simple no?
        public BigInteger ModDivide(BigInteger b, BigInteger n) {
        BigInteger inverse = b.ModInverse(n);
        return a.ModMultiply(inverse,n);
        }

        /// <summary>
        /// Computes this^e (mod n).
        /// </summary>
        /// <param name="e">The exponent (must be non-negative).</param>
        /// <param name="n">The modulus (must be positive).</param>
        /// <returns>The result of b^e (mod n).</returns>
        /// <remarks>
        /// You must implement this function efficiently.
        /// At most, you may use <see cref="ModMultiply" /> Ceiling(log2(base)) + #bits_set(exponent)) times.
        /// You are only allowed a single <see cref="BigInteger"/> for local variables.
        /// </remarks>
       public BigInteger ModExp(BigInteger e, BigInteger n) {
        BigInteger result = 1;
        while(e > 0){
            if(e%2 == 1){
                result = result.ModMultiply(a,n);
            }
            a = a.ModMultiply(a,n);
            e = e / 2;

        }
        return result;
        }

    }
}