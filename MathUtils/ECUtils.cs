using System.Numerics;

namespace MathUtils;

/// <summary>
/// Represents an elliptic curve over a finite field.
/// </summary>
public readonly record struct ECCurve {

    #region Members

    /// <summary>Linear coefficient <c>A</c> of the curve equation.</summary>
    public BigInteger A { get; }

    /// <summary>Constant coefficient <c>B</c> of the curve equation.</summary>
    public BigInteger B { get; }

    /// <summary>Prime modulus of the curve.</summary>
    public BigInteger P { get; }

    #endregion

    #region Constructor

    /// <summary>
    /// Initializes a new instance of the <see cref="ECCurve"/> struct with the specified coefficients and prime modulus.
    /// </summary>
    /// <param name="a">The coefficient <c>A</c>.</param>
    /// <param name="b">The coefficient <c>B</c>.</param>
    /// <param name="p">The prime modulus <c>P</c>.</param>
    /// <exception cref="ArgumentException">Thrown when the given parameters do not produce a non-singular elliptic curve.</exception>
    public ECCurve(BigInteger a, BigInteger b, BigInteger p) {
        if(!IsValidCurve(a,b,p)){
            throw new ArgumentException();
        }else{
            //If the curve is valid, I just make sure A and B are within range. I think this math works?
            //Update: Had to go looking for the A and B equations. They normalize A and B to be within range.
            P = p;
            A = (a%p+p)%p;
            B = (b%p+p)%p;
        }
    }

    #endregion

    #region Operation

    /// <summary>
    /// Deconstructs the elliptic curve into its constituent components.
    /// </summary>
    /// <param name="a">Outputs the linear coefficient <c>A</c>.</param>
    /// <param name="b">Outputs the constant coefficient <c>B</c>.</param>
    /// <param name="p">Outputs the prime modulus <c>P</c>.</param>
    /// <remarks>
    /// Your implementation needs to make sure the point is on the curve.
    /// </remarks>
    public void Deconstruct(out BigInteger a, out BigInteger b, out BigInteger p) {
        a = A;
        b = B;
        p = P;
    }

    /// <summary>
    /// Determines whether the specified coefficients and prime modulus form a valid (non-singular) elliptic curve.
    /// </summary>
    /// <param name="a">The coefficient <c>A</c>.</param>
    /// <param name="b">The coefficient <c>B</c>.</param>
    /// <param name="p">The prime modulus <c>P</c>.</param>
    /// <returns><see langword="true"/> if the discriminant is non-zero modulo <c>P</c>.</returns>
    public static bool IsValidCurve(BigInteger a, BigInteger b, BigInteger p) {
    BigInteger result = (4*BigInteger.Pow(a,3)+ 27*BigInteger.Pow(b,2));
    if(result % p == 0){
        return false;
    }
        return true;
    }

    /// <summary>
    /// Constructs a point on the curve y² ≡ x³ + Ax + B (mod P).
    /// </summary>
    /// <param name="x">X coordinate.</param>
    /// <param name="y">Y coordinate.</param>
    /// <returns>ECPoint for the given x and y.</returns>
    public ECPoint GetPoint(BigInteger x, BigInteger y)
    {
        x = ((x % P)+P)%P;
        y = ((y % P)+P)%P;
        if (!AreCoordinatesOnCurve(x, y))
        {
            throw new ArgumentException();
        }

        return new ECPoint(this,x,y);
    }

    /// <summary>
    /// Checks if the given coordinates are on the curve.
    /// </summary>
    /// <param name="x">X coordinate.</param>
    /// <param name="y">Y coordinate.</param>
    /// <returns>True if the coordinates are on the curve, false otherwise.</returns>
    public bool AreCoordinatesOnCurve(BigInteger x, BigInteger y) {
        BigInteger right_side = (BigInteger.Pow(x,3)+ A*x + B) % P;
        right_side = (right_side+P)%P;
        
        if((y+P)%P == right_side){
            return true;
        }
        return false;
    }
    #endregion
}

/// <summary>
/// Represents a point on an elliptic curve, or the identity element (point at infinity).
/// </summary>
public readonly record struct ECPoint {

    #region Members

    /// <summary>Gets the elliptic curve to which this point belongs.</summary>
    private ECCurve E { get; }

    /// <summary>Gets the x-coordinate of the point.</summary>
    public BigInteger X { get; }

    /// <summary>Gets the y-coordinate of the point.</summary>
    public BigInteger Y { get; }

    #endregion

    #region Point at infinity

    /// <summary>Gets the identity element (point at infinity) for elliptic curve arithmetic.</summary>
    public static ECPoint PointAtInfinity { get; } = default;

    #endregion

    #region Constructor

    /// <summary>
    /// Constructs a finite point on the given curve.
    /// </summary>
    /// <param name="e">Curve the point belongs to.</param>
    /// <param name="x">X coordinate of the point (must be non-negative).</param>
    /// <param name="y">Y coordinate of the point (must be non-negative).</param>
    internal ECPoint(ECCurve e, BigInteger x, BigInteger y) {
        E = e;
        X = x;
        Y = y;
    }

    #endregion

    #region Operation

    /// <summary>
    /// Deconstructs the point into its associated curve and coordinates.
    /// </summary>
    /// <param name="e">Outputs the curve.</param>
    /// <param name="x">Outputs the x-coordinate.</param>
    /// <param name="y">Outputs the y-coordinate.</param>
    public void Deconstruct(out ECCurve e, out BigInteger x, out BigInteger y) {
        e = E;
        x = X;
        y = Y;
    }

    #endregion

    #region Operator overloads

    /// <summary>
    /// Negates the specified point, producing its additive inverse on the curve.
    /// </summary>
    /// <param name="value">The point to negate.</param>
    /// <returns>The negated point.</returns>
    public static ECPoint operator -(ECPoint value) {
       //This is the identity, attempting to invert p.a.i returns itself.
       if(value.Equals(PointAtInfinity)){
        return PointAtInfinity;
       }
       BigInteger negative_y = ((-value.Y)%value.E.P+value.E.P)%value.E.P;
       return new ECPoint (value.E,value.X,negative_y);
    }

    /// <summary>
    /// Adds two points on an elliptic curve.
    /// </summary>
    /// <param name="lhs">The first point.</param>
    /// <param name="rhs">The second point.</param>
    /// <returns>The resulting point of the addition.</returns>
    /// <exception cref="ArgumentException">Thrown when attempting to add points from different elliptic curves.</exception>
    public static ECPoint operator +(ECPoint lhs, ECPoint rhs) {
      //Identity Checks for infinite point
      if(lhs.Equals(PointAtInfinity)){
        return rhs;
      }
      if(rhs.Equals(PointAtInfinity)){
        return lhs;
      }
      if(lhs.E != rhs.E){
        throw new ArgumentException();
      }
      //If they are mirrors of each other,two points inverted and added together mod p should be zero I think.
      if(lhs.X == rhs.X && ((lhs.Y + rhs.Y) % lhs.E.P == 0)){
        return PointAtInfinity;
      }

      //Doubling Equation Work since they are the same point
      if(lhs.X == rhs.X && lhs.Y == rhs.Y){  
        BigInteger top = (3*BigIntegerExtensions.ModExp(lhs.X,2,lhs.E.P)+lhs.E.A)%lhs.E.P;
        BigInteger bottom = BigIntegerExtensions.ModInverse(2*lhs.Y,lhs.E.P);
        BigInteger lamb = ((top * bottom) % lhs.E.P+lhs.E.P)%lhs.E.P;
        BigInteger new_x_1 = ((BigInteger.Pow(lamb, 2) - 2 * lhs.X) % lhs.E.P + lhs.E.P) % lhs.E.P;
        BigInteger new_y_1 = ((lamb * (lhs.X - new_x_1) - lhs.Y) % lhs.E.P + lhs.E.P) % lhs.E.P;
        return new ECPoint(lhs.E, new_x_1, new_y_1);
      }
      //Catch All math (not same point, no inifinity point stuff)
      //lambda = (y_1 - y_2)/(x_1 - x_2);
      //x_3 = lambda^2 - x_1 - x_2;
      //y_3 = lambda(x_1 - x_3) - y_1;
         BigInteger lambda = (((lhs.Y - rhs.Y) * BigIntegerExtensions.ModInverse(lhs.X - rhs.X, lhs.E.P)) % lhs.E.P+ lhs.E.P) % lhs.E.P;
      BigInteger new_x = ((BigInteger.Pow(lambda, 2) - lhs.X - rhs.X) % lhs.E.P + lhs.E.P) % lhs.E.P;
      BigInteger new_y = ((lambda * (lhs.X - new_x) - lhs.Y) % lhs.E.P + lhs.E.P) % lhs.E.P;
      return new ECPoint(lhs.E, new_x, new_y);
    }


    /// <summary>
    /// Multiplies an elliptic curve point by a scalar using double-and-add scalar multiplication.
    /// </summary>
    /// <param name="k">The scalar multiplier.</param>
    /// <param name="point">The point to multiply.</param>
    /// <returns>The point <c>k * point</c>.</returns>
    /// <remarks>
    /// You must implement this function efficiently.
    /// At most, you may use <see cref="operator +" /> Ceiling(log2(base)) + #bits_set(k)) times.
    /// You are only allowed a single <see cref="ECPoint"/>  for local variables.
    /// </remarks>
    

 public static ECPoint operator *(BigInteger k, ECPoint point) {
    //Inverese/negative point checking to make the math easy.
        if (k < 0) {
            k = -k;
            point = -point;
        }
 
        ECPoint result = PointAtInfinity;
 //This section is basically just a rip of my prior implimentation of Xtimes
        while (k > 0) {
            if ((k & 1) == 1) {
                result = result + point;
            }
            point = point + point;
            k >>= 1;

        }
 
        return result;
    }
    #endregion
}
