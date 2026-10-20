using System.Numerics;
using System.Security.Cryptography;
using MathUtils;

namespace AsymmetricCryptography;

/// <summary>
/// Implementation of RSA.
/// </summary>
public class RSA {

    #region Record types

    /// <summary>
    /// RSA group parameters.
    /// </summary>
    /// <param name="Modulus">The modulus for group operations.</param>
    public record struct Parameters(BigInteger Modulus);

    /// <summary>
    /// RSA public key.
    /// </summary>
    /// <param name="Exponent">The public exponent.</param>
    /// <param name="Parameters">The group parameters.</param>
    public sealed record PublicKey(BigInteger Exponent, Parameters Parameters);

    /// <summary>
    /// RSA private key.
    /// </summary>
    /// <param name="Exponent">The private exponent.</param>
    /// <param name="Parameters">The group parameters.</param>
    public sealed record PrivateKey(BigInteger Exponent, Parameters Parameters);

    /// <summary>
    /// A RSA key pair.
    /// </summary>
    /// <param name="PublicKey">The public key.</param>
    /// <param name="PrivateKey">The private key.</param>
    public record struct KeyPair(PublicKey PublicKey, PrivateKey PrivateKey);

    #endregion

    #region Configuration

    /// <summary>
    /// The smallest modulus size, in bits, this implementation will generate or accept.
    /// </summary>
    public const int MinimumBitLength = 1024;

    /// <summary>The default public exponent (F4).</summary>
    private static readonly BigInteger DefaultExponent = 65537;

    #endregion

    #region Members

    private readonly PublicKey _PublicKey;
    private readonly PrivateKey? _PrivateKey;

    private BigInteger N => _PublicKey.Parameters.Modulus;

    /// <summary>Number of bytes needed to hold the modulus.</summary>
    public int ModulusByteCount => (int)((N.GetBitLength() + 7) / 8);

    #endregion

    #region Key retrieval

    /// <summary>Returns the public key held by this instance.</summary>
    public PublicKey GetPublicKey() => _PublicKey;

    /// <summary>Returns the private key held by this instance.</summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when this instance was constructed from a public key only.
    /// </exception>
    public PrivateKey GetPrivateKey() =>
        _PrivateKey ?? throw new InvalidOperationException("No private key is held.");

    /// <summary>Returns the public/private key pair.</summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when this instance was constructed from a public key only.
    /// </exception>
    public KeyPair GetKeyPair() =>
        new(_PublicKey, _PrivateKey ?? throw new InvalidOperationException("No private key is held."));

    #endregion

    #region Constructors

    /// <summary>
    /// Create an RSA instance. Generates parameters and key pair.
    /// </summary>
    /// <param name="bitLength">Modulus size in bits.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="bitLength"/> is below <see cref="MinimumBitLength"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="bitLength"/> is odd.</exception>
    public RSA(int bitLength) : this(bitLength, DefaultExponent) { }

    /// <summary>
    /// Create an RSA instance. Generates parameters and key pair for a fixed e value.
    /// </summary>
    /// <param name="bitLength">Modulus size in bits.</param>
    /// <param name="publicExponent">A fixed public exponent.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="bitLength"/> is below <see cref="MinimumBitLength"/>, or the exponent is not odd and at least 3.
    /// </exception>
    /// <exception cref="ArgumentException"><paramref name="bitLength"/> is odd.</exception>
    public RSA(int bitLength, BigInteger publicExponent) : this(GenerateKeyPair(bitLength, publicExponent)) { }

    /// <summary>
    /// Wraps an existing public key. The resulting instance can encrypt and verify but not
    /// decrypt or sign.
    /// </summary>
    /// <param name="publicKey">The public key to use.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The modulus is not a positive odd integer of at least <see cref="MinimumBitLength"/> bits,
    /// or the exponent is not odd and in <c>[3, n)</c>.
    /// </exception>
    public RSA(PublicKey publicKey) {
        if (publicKey is null)
            throw new ArgumentNullException(nameof(publicKey));

        BigInteger n = publicKey.Parameters.Modulus;
        BigInteger e = publicKey.Exponent;

        if (n.Sign <= 0 || n.IsEven || n.GetBitLength() < MinimumBitLength)
            throw new ArgumentOutOfRangeException(nameof(publicKey),
                "Modulus must be a positive odd integer of at least the minimum bit length.");

        if (e.IsEven || e < 3 || e >= n)
            throw new ArgumentOutOfRangeException(nameof(publicKey),
                "Public exponent must be odd and in [3, n).");

        _PublicKey = publicKey;
        _PrivateKey = null;
    }

    /// <summary>
    /// Wraps an existing key pair.
    /// </summary>
    /// <param name="keyPair">The key pair to adopt.</param>
    /// <exception cref="ArgumentOutOfRangeException">The private exponent is outside <c>[1, n)</c>, or the public half is malformed.</exception>
    /// <exception cref="ArgumentException">The private key does not match the public key.</exception>
    public RSA(KeyPair keyPair) : this(keyPair.PublicKey) {
        PrivateKey priv = keyPair.PrivateKey ?? throw new ArgumentNullException(nameof(keyPair));
        BigInteger n = N;
        BigInteger e = _PublicKey.Exponent;

        if (priv.Exponent < 1 || priv.Exponent >= n)
            throw new ArgumentOutOfRangeException(nameof(keyPair), "Private exponent is out of range.");

        if (priv.Parameters != _PublicKey.Parameters)
            throw new ArgumentException("Private and public key parameters do not match.", nameof(keyPair));

        // test values: (m^e)^d must give back m.
        // Also why is C# have python syntaxing sometimes
        // Double ALSO I asked for clarificaiton on syntaxting on this section with AI. just conceptually.
        foreach (BigInteger test in new BigInteger[] { 2, 3, n - 2 }) {
            BigInteger c = BigInteger.ModPow(test, e, n);
            if (BigInteger.ModPow(c, priv.Exponent, n) != test)
                throw new ArgumentException("Private key does not match the public key.", nameof(keyPair));
        }

        _PrivateKey = priv;
    }

    private static KeyPair GenerateKeyPair(int bitLength, BigInteger e) {
      //Same error checks we have had.
        if (bitLength < MinimumBitLength)
            throw new ArgumentOutOfRangeException(nameof(bitLength), "Bit length is too small RSA GenKeyPair.");
        if (bitLength % 2 != 0)
            throw new ArgumentException("Bit length must be even RSA GenKeyPair.", nameof(bitLength));
        if (e.IsEven || e < 3 || e.GetBitLength() >= bitLength / 2)
            throw new ArgumentOutOfRangeException(nameof(e), "exponent is wrong RSA GenKeyPair.");

        int half = bitLength / 2;
        BigInteger minGap = BigInteger.One << (half - 100);
        BigInteger minD = BigInteger.One << half;

        while (true) {
            BigInteger p = GetRandomPrime(half);
            BigInteger q = GetRandomPrime(half);

            if (BigInteger.Abs(p - q) < minGap) continue;

            BigInteger n = p * q;
            if (n.GetBitLength() != bitLength) continue;

            BigInteger pm1 = p - 1, qm1 = q - 1;
            if (!BigInteger.GreatestCommonDivisor(e, pm1).IsOne) continue;
            if (!BigInteger.GreatestCommonDivisor(e, qm1).IsOne) continue;

            BigInteger lambda = pm1 / BigInteger.GreatestCommonDivisor(pm1, qm1) * qm1;
            BigInteger d = BigIntegerExtensions.ModInverse(e, lambda);
            if (d <= minD) continue;

            Parameters prm = new(n);
            return new KeyPair(new PublicKey(e, prm), new PrivateKey(d, prm));
        }
    }

    #endregion
    private static BigInteger FromBytes(ReadOnlySpan<byte> bytes) =>
        new(bytes, isUnsigned: true, isBigEndian: true);

    private static byte[] ToFixedBytes(BigInteger v, int length) {
        byte[] raw = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length > length){
        throw new ArgumentException("Value does not fit in the requested length.");
        }
        byte[] result = new byte[length];
        raw.CopyTo(result, length - raw.Length);
        return result;
    }

    /// <summary>
    /// Computes x^d mod n with multiplicative blinding, so the exponentiation never runs
    /// directly on attacker-chosen input.
    /// </summary>
    private BigInteger PrivateOperation(BigInteger x) {
        BigInteger n = N;
        BigInteger e = _PublicKey.Exponent;
        BigInteger d = (_PrivateKey ?? throw new InvalidOperationException("No private key is held.")).Exponent;

        BigInteger r;
        //Same Randomization style ive been doing
        do {
            r = RandomBigInteger(2, n - 1);
        } while (!BigInteger.GreatestCommonDivisor(r, n).IsOne);

        
        BigInteger blinded = x * BigInteger.ModPow(r, e, n) % n;
        BigInteger y = BigInteger.ModPow(blinded, d, n);
        return y * BigIntegerExtensions.ModInverse(r, n) % n;
    }


    private static byte[] OaepEncode(OAEPEncoder encoder, ReadOnlySpan<byte> plaintext, int blockLength) =>
        encoder.Encode(plaintext, blockLength);

    private static byte[] OaepDecode(OAEPEncoder encoder, byte[] block) =>
        encoder.Decode(block);


    #region Encryption operations

    /// <summary>
    /// Encrypts a message using OAEP with SHA-256 and an empty label.
    /// </summary>
    /// <param name="plaintext">The message to encrypt.</param>
    /// <returns>A ciphertext <see cref="ModulusByteCount"/> bytes long.</returns>
    /// <exception cref="ArgumentException">The plaintext is too long for the modulus.</exception>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext) => Encrypt(plaintext, new OAEPEncoder(HashAlgorithmName.SHA256));

    /// <summary>
    /// Encrypts a message using a caller-supplied OAEP encoder.
    /// </summary>
    /// <param name="plaintext">The message to encrypt.</param>
    /// <param name="encoder">The OAEP encoder supplying the hash, MGF1 hash, and label.</param>
    /// <returns>A ciphertext <see cref="ModulusByteCount"/> bytes long.</returns>
    /// <exception cref="ArgumentException">The plaintext exceeds the encoder's capacity for this modulus.</exception>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, OAEPEncoder encoder) {
        ArgumentNullException.ThrowIfNull(encoder);

        int k = ModulusByteCount;
        if (plaintext.Length > encoder.GetMaxMessageLength(k))
            throw new ArgumentException("The plaintext is too long for this modulus.", nameof(plaintext));

        byte[] block = OaepEncode(encoder, plaintext, k);
        BigInteger m = FromBytes(block);
        if (m >= N)
            throw new ArgumentException("Encoded message is not smaller than the modulus.", nameof(plaintext));

        BigInteger c = BigInteger.ModPow(m, _PublicKey.Exponent, N);
        return ToFixedBytes(c, k);
    }

    /// <summary>
    /// Decrypts a ciphertext produced with OAEP using SHA-256 and an empty label.
    /// </summary>
    /// <param name="ciphertext">The ciphertext, which must be <see cref="ModulusByteCount"/> bytes.</param>
    /// <returns>The recovered plaintext.</returns>
    /// <exception cref="InvalidOperationException">No private key is held.</exception>
    /// <exception cref="ArgumentException">The ciphertext is the wrong length, too large, or fails OAEP checks.</exception>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext) => Decrypt(ciphertext, new OAEPEncoder(HashAlgorithmName.SHA256));

    /// <summary>
    /// Decrypts a ciphertext using a caller-supplied OAEP encoder.
    /// </summary>
    /// <param name="ciphertext">The ciphertext, which must be <see cref="ModulusByteCount"/> bytes.</param>
    /// <param name="encoder">An encoder configured identically to the one used to encrypt.</param>
    /// <returns>The recovered plaintext.</returns>
    /// <exception cref="InvalidOperationException">No private key is held.</exception>
    /// <exception cref="ArgumentException">The ciphertext is the wrong length, too large, or fails OAEP checks.</exception>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, OAEPEncoder encoder) {
      //Argument Exception as requested.
        if (_PrivateKey == null)
            throw new InvalidOperationException("No private key is held.");
        ArgumentNullException.ThrowIfNull(encoder);
        const string Fail = "Invalid ciphertext.";

        int k = ModulusByteCount;
        if (ciphertext.Length != k)
            throw new ArgumentException(Fail, nameof(ciphertext));

        BigInteger c = FromBytes(ciphertext);
        if (c >= N)
            throw new ArgumentException(Fail, nameof(ciphertext));

        try {
            BigInteger m = PrivateOperation(c);
            return OaepDecode(encoder, ToFixedBytes(m, k));
        } catch (Exception) {
            throw new ArgumentException(Fail, nameof(ciphertext));
        }
    }

    #endregion

    #region Signing operations

    /// <summary>
    /// Signs data using PSS with SHA-256.
    /// </summary>
    /// <param name="data">The data to sign; it is hashed internally.</param>
    /// <returns>A signature <see cref="ModulusByteCount"/> bytes long.</returns>
    /// <exception cref="InvalidOperationException">No private key is available.</exception>
    public byte[] Sign(ReadOnlySpan<byte> data) => Sign(data, new PSSEncoder(HashAlgorithmName.SHA256));

    /// <summary>
    /// Signs data using a caller-supplied PSS encoder. Because PSS salts every signature,
    /// signing the same data twice yields different signatures.
    /// </summary>
    /// <param name="data">The data to sign; it is hashed internally.</param>
    /// <param name="pss">The PSS encoder supplying the hash and MGF1 hash.</param>
    /// <returns>A signature <see cref="ModulusByteCount"/> bytes long.</returns>
    /// <exception cref="InvalidOperationException">No private key is held, or the modulus is too small for this encoder.</exception>
    public byte[] Sign(ReadOnlySpan<byte> data, PSSEncoder pss) {
      //ANOTHER error check
        if (_PrivateKey is null)
            throw new InvalidOperationException("No private key is held.");
        ArgumentNullException.ThrowIfNull(pss);

        int emBits = (int)N.GetBitLength() - 1;

        //temp byte array
        byte[] em;
        try {
          //If this fails we throw an exception
            em = pss.Encode(data, emBits);
        } catch (ArgumentOutOfRangeException ex) {
            throw new InvalidOperationException("The modulus is too small for this.", ex);
        }

        BigInteger m = FromBytes(em);
        BigInteger s = PrivateOperation(m);
        return ToFixedBytes(s, ModulusByteCount);
    }

    /// <summary>
    /// Verifies a PSS signature using SHA-256.
    /// </summary>
    /// <param name="data">The data that was supposedly signed.</param>
    /// <param name="signature">The signature to check.</param>
    /// <returns><see langword="true"/> if the signature is valid for this key.</returns>
    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) => Verify(data, signature, new PSSEncoder(HashAlgorithmName.SHA256));

    /// <summary>
    /// Verifies a PSS signature using a caller-supplied PSS encoder. Malformed input is reported
    /// as <c>false</c> rather than thrown, so callers need only one failure path.
    /// </summary>
    /// <param name="data">The data that was supposedly signed.</param>
    /// <param name="signature">The signature to check.</param>
    /// <param name="pss">An encoder configured identically to the one used to sign.</param>
    /// <returns><see langword="true"/> if the signature is valid for this key.</returns>
    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, PSSEncoder pss) {
      //Gotta love a try catch fr (not raelly they kinda suck oops)
        try {
            if (pss is null){

            return false;
            } 

            int k = ModulusByteCount;
            if (signature.Length != k) return false;

            BigInteger s = FromBytes(signature);
            if (s >= N){
              return false;
            } 

            int emBits = (int)N.GetBitLength() - 1;
            int emLen = (emBits + 7) / 8;

            BigInteger m = BigInteger.ModPow(s, _PublicKey.Exponent, N);
            if (m.GetBitLength() > emBits) {
              return false;
            }
            return pss.Verify(data, ToFixedBytes(m, emLen), emBits);
        } catch (Exception) {
            return false;
        }
    }

    #endregion

}
