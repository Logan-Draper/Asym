using System.Numerics;
using System.Security.Cryptography;
using MathUtils;

namespace AsymmetricCryptography;

/// <summary>
/// Implementation of unauthenticated Diffie-Hellman.
/// </summary>
public class DiffieHellman {

    #region Record types

    /// <summary>
    /// Diffie-Hellman group parameters.
    /// </summary>
    /// <param name="Modulus">The modulus for group operations.</param>
    /// <param name="Generator">The generator for group operations.</param>
    /// <param name="Order">The order of the generator <c>g</c>.</param>
    public record struct Parameters(BigInteger Modulus, BigInteger Generator, BigInteger Order);

    #endregion

    #region Configuration

    /// <summary>The smallest modulus bit length this implementation will generate.</summary>
    public const int MinimumBitLength = 32;

    #endregion

    #region Key retrieval

    /// <summary>Returns the parameters held by this instance.</summary>
    public Parameters GetParameters(){
      return this;
    }
    /// <summary>Returns the public key held by this instance.</summary>
    public BigInteger GetPublicValue() {
      return this;
    }

    #endregion

    #region Constructors

    /// <summary>
    /// Create an Diffie-Hellman instance. Generates parameters and key pair.
    /// </summary>
    /// <param name="bitLength">Modulus size in bits.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="bitLength"/> is below <see cref="MinimumBitLength"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="bitLength"/> is odd.</exception>
    public DiffieHellman(int bitLength) {
    if(bitLength < 32){

      throw new ArgumentOutOfRangeException("BitLength is NOT at least 32 bits");
    }if(bitLength %2 != 0){
    
      throw new ArgumentException("BitLength is not Even.");
    }
    BigInteger q,p;
  //This simply ensures the relationship between q and p, such that they are related and both prime.
    do{
      q = GetRandomPrime(bitLength-1); 
      p = 2*q+1;
      
      //Not sure how many primarily rounds we are doing, MathUtils defaults to 40
    }while(!IsProbablePrime(p));
    BigInteger g;
    //This creates a generator that is a subset of P.
    do{
      BigInteger h = RandomBigInteger(2,p-1);
      g = BigInteger.ModPow(h,2,p);
    }while(g==1);

     _parameters = new Parameters(p, g, q);
    _privateKey = RandomBigInteger(1, q); 
    _publicValue = BigInteger.ModPow(g, _privateKey, p);
    }

    /// <summary>
    /// Create an Diffie-Hellman instance. Generates a key pair for the provided parameters.
    /// </summary>
    /// <param name="parameters">Parameters to use when generating the key pair.</param>
    public DiffieHellman(Parameters parameters) {
      //
      if(parameters.Modulus < 3){
        throw new ArgumentException("Parameters in Contructor 2 are Wrong.");
      }
      if(parameters.Generator < 2 || parameters.Generator >= parameters.Modulus){
        throw new ArgumentException("Parameters in Contructor 2 are Wrong.");
      }

      //This is just the genuine relationship between these. if this isn't true we just shouldn't proceed. 
      if (BigInteger.ModPow(parameters.Generator, parameters.Order, parameters.Modulus) != 1){
    throw new ArgumentException("Generator does not have the stated order.");
      }
      _parameters = parameters;
      _privateKey = RandomBigInteger(1,parameters.Order);
      _publicValue = BigInteger.ModPow(parameters.Generator,_privateKey,parameters.Modulus);
    }

    #endregion

    #region Operations

    /// <summary>
    /// Combines a received public value with the local private key to calculate a shared value.
    /// </summary>
    /// <param name="receivedPublicValue">The peer's public value.</param>
    /// <returns>The calculated shared value.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="receivedPublicValue"/> is not within the group.</exception>
    public BigInteger ComputeSharedValue(BigInteger receivedPublicValue) {

    if (receivedPublicValue < 2 || receivedPublicValue > _parameters.Modulus - 2){
        throw new ArgumentOutOfRangeException("Modulus not in range.");
    }

    if (BigInteger.ModPow(receivedPublicValue, _parameters.Order, _parameters.Modulus) != 1){
        throw new ArgumentOutOfRangeException("Public value is not in the group.");
    }

    //Some error checks, then just a simple return of the shared value.
    return BigInteger.ModPow(receivedPublicValue, _privateKey, p);
    }
    /// <summary>
    /// Combines a received public value with the local private key to derive a shared key using HKDF w/ SHA-512.
    /// </summary>
    /// <param name="receivedPublicValue">The peer's public value.</param>
    /// <param name="byteCount">The desired number of bytes in the shared key.</param>
    /// <returns>A shared key derived from calculating shared value.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="receivedPublicValue"/> is not within the group or byteCount is not positive.</exception>
    /// <remarks>
    /// Use <see cref="HKDF.DeriveKey" /> method to generate a key, using <see cref="HashAlgorithmName.SHA512"/>
    /// as the hash algorithm.
    /// </remarks>
    public byte[] ComputeSharedKey(BigInteger receivedPublicValue, int byteCount) {
      //Byte count cant be odd
          if (byteCount <= 0){
        throw new ArgumentOutOfRangeException("byte count invalid oopsy!");
          }

    BigInteger shared = ComputeSharedValue(receivedPublicValue);
    byte[] ikm = shared.ToByteArray(isUnsigned: true, isBigEndian: true);

    //Function specified in the summary
    return HKDF.DeriveKey(HashAlgorithmName.SHA512, ikm, byteCount);
    }
    #endregion

}
