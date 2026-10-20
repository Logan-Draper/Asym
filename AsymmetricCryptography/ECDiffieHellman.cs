using System.Numerics;
using System.Security.Cryptography;

using ECCurve = MathUtils.ECCurve;
using ECPoint = MathUtils.ECPoint;
using Parameters = AsymmetricCryptography.ECParameters.Parameters;

namespace AsymmetricCryptography;

/// <summary>
/// Implementation of unauthenticated Elliptic Curve Diffie-Hellman key agreement over a
/// prime-order subgroup of the multiplicative group of integers modulo a safe prime.
/// </summary>
public class ECDiffieHellman {

    #region Members

    /// <summary>The curve parameters.</summary>
    private readonly Parameters parameters;

    /// <summary>The public key.</summary>
    private readonly ECPoint publicKey;

    /// <summary>The private key.</summary>
    private readonly BigInteger privateKey;

    #endregion

    #region Key retrieval

    /// <summary>Returns the parameters held by this instance.</summary>
    public Parameters GetParameters() => parameters;

    /// <summary>Returns the public key held by this instance.</summary>
    /// Why would you not just give us these, it feels REALLY simple to not just give it. but ok.
    public ECPoint GetPublicValue() => publicKey;
    #endregion

    #region Constructors

    /// <summary>
    /// Create an Diffie-Hellman instance. Generates a key pair for the provided parameters.
    /// </summary>
    /// <param name="parameters">Parameters to use when generating the key pair.</param>
    public ECDiffieHellman(Parameters parameters) {
      ECPoint g = parameters.Generator;
      BigInteger n = parameters.Order;

          if (n < 2)
        throw new ArgumentException("Order must be at least 2.", nameof(parameters));
    if (g == ECPoint.PointAtInfinity)
        throw new ArgumentException("Generator cannot be the point at infinity.", nameof(parameters));
    if (n * g != ECPoint.PointAtInfinity)
        throw new ArgumentException("Generator does not have the stated order.", nameof(parameters));

    this.parameters = parameters;
    privateKey = RandomScalar(n);
    publicKey = privateKey * g;

    }

    #endregion

    #region Operations

    /// <summary>
    /// Combines a received public point with the local private key to calculate a shared point.
    /// </summary>
    /// <param name="receivedPublicPoint">The peer's public point.</param>
    /// <returns>The calculated shared point.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="receivedPublicPoint"/> is not within the group.</exception>
    public ECPoint ComputeSharedPoint(ECPoint receivedPublicPoint) {
         if (receivedPublicPoint == ECPoint.PointAtInfinity){
           throw new ArgumentOutofRangeException("Point is at infinity.. it cant be there lol");
         }

    receivedPublicPoint.Deconstruct(out ECCurve curve, out BigInteger x, out BigInteger y);


    if (curve != CurveOf(parameters.Generator) || !curve.AreCoordinatesOnCurve(x, y)){
        throw new ArgumentOutOfRangeException("Point is not on the curve.");
    }

    // Subgroup check (blocks small-order points)
    if (parameters.Order * receivedPublicPoint != ECPoint.PointAtInfinity){
        throw new ArgumentOutOfRangeException("Point is not in the group.");
    }
    return privateKey * receivedPublicPoint;
    }

    /// <summary>
    /// Combines a received public point with the local private key to derive a shared key using HKDF w/ SHA-512.
    /// </summary>
    /// <param name="receivedPublicPoint">The peer's public point.</param>
    /// <param name="byteCount">The desired number of bytes in the shared key.</param>
    /// <returns>The calculated shared value.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="receivedPublicPoint"/> is not within the group.</exception>
    /// <remarks>
    /// Use <see cref="HKDF.DeriveKey" /> method to generate a key, using <see cref="HashAlgorithmName.SHA512"/>
    /// as the hash algorithm.
    /// </remarks>
    public byte[] ComputeSharedKey(ECPoint receivedPublicPoint, int byteCount) {
          if (byteCount <= 0){
        throw new ArgumentOutOfRangeException(nameof(byteCount), "Must be positive.");
          }

    ECPoint shared = ComputeSharedPoint(receivedPublicPoint);
    byte[] ikm = shared.X.ToByteArray(isUnsigned: true, isBigEndian: true);
    return HKDF.DeriveKey(HashAlgorithmName.SHA512, ikm, byteCount);
}

private static ECCurve CurveOf(ECPoint p) {
  //I hope this is proper form/calling conventions
    p.Deconstruct(out ECCurve e, out _, out _);
    return e;
}

private static BigInteger RandomScalar(BigInteger upperExclusive) {
    int byteLength = (int)((upperExclusive.GetBitLength() + 7) / 8);
    BigInteger value;
    do {
        byte[] bytes = RandomNumberGenerator.GetBytes(byteLength);
        value = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
    } while (value < 1 || value >= upperExclusive);
    return value;
    }

    #endregion
}
