namespace MathUtils;

/// <summary>
/// Base class for implementing an Echo client.
/// </summary>
public static class GFUtils {

    /// <summary>
    /// The irreducible polynial for GF(2^8) used in AES (x^8 + x^4 + x^3 + x + 1).
    /// </summary>
    private const byte AESIrreduciblePolynomial = 0x1b;

    /// <summary>
    /// Calculates x * a(x) (mod p(x)) in GF(2^8).
    /// </summary>
    /// <param name="a">a(x).</param>
    /// <param name="p">p(x).</param>
    /// <returns>x * a(x) (mod p(x)) in GF(2^8).</returns>
    /// 
    /// GOAL: shift to the left or right once, if I overflow I need to mod by P?
    public static byte XTimes(byte a, byte p = AESIrreduciblePolynomial) {

        //cast the result back to a byte so that C# doesn't do a promotion. 
        //Multiplication by "x"
        byte b = (byte)(a << 1);
        //If it goes over x^7th, it would be greater than or equal to: 0b1000_0000 or 0x80.
        if(a >= 0x80){
            //Overflow handle to loop back over the field.
        b = (byte)(b ^ p);
        }
        return b;
    }

    /// <summary>
    /// Calculates a(x) * b(x) mod (mod p(x)) in GF(2^8).
    /// </summary>
    /// <param name="a">a(x)</param>
    /// <param name="b">b(x)</param>
    /// <returns>a(x) * b(x) mod (mod p(x)) in GF(2^8).</returns>
    /// <remarks>
    /// You must implement this function efficiently.
    /// At most, you may call <see cref="XTimes" /> at most seven times.
    /// You must calculate values as you go, not create a collection that stores values.
    /// </remarks>
    public static byte GFMultiply(byte a, byte b, byte p = AESIrreduciblePolynomial) {
        byte res = 0;
        //My strategy is to loop over every bit of b, and then once all of the bits have been shifted off of b, at a maximum of 7 times, 
        // then this condition stops being true and we can end the loop. This is the only way in my brain that this could possibly make sense
        while(b != 0){

            //If the specific bit we are looking at (least significant) is 1, and it is anded with 1,
            //  then the result is one and this if condition should trigger. Then we XOR the current result with a.
            if (b == 1)
            {
                res ^= a;
            }
            //We call xtimes every time to "multiple by x" again. basically shifting every bit to the left and handling the overflow.
            a = XTimes(a,p);
            b = (byte)(b >> 1);
        }
        return res;
    }

}