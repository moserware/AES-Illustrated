using System;
using System.Collections;
using System.Linq;

namespace Moserware.AesIllustrated
{
    /// <summary>
    /// Performs mathematical operations in Rijndael's finite field (GF[2^8] for the Galois fans out there).
    /// </summary>
    /// <remarks>For performance reasons, most functions are just table lookups.
    /// However, to be instructive, there are "Calculate" functions that actually do the
    /// real math. These are used by the functions that create the tables. 
    /// </remarks>
    internal static class FiniteFieldMath
    {
        private static byte[] _AntiLogTable;
        private static byte[] _FTable;
        private static byte[] _GTable;
        private static byte[] _InvFTable; // Technically this isn't needed since we compute the s-box inverse without needing it.
        private static byte[] _LogTable;

        /// <summary>
        /// Calculates x * b(x) mod m(x) where b(x) is represented by <paramref name="b"/> and
        /// m(x) is the Rijndael polynomial x^8 ⊕ x^4 ⊕ x^3 ⊕ x ⊕ 1 = 0x11B.
        /// </summary>
        /// <remarks>For more details, see page 16 of 
        /// "The Design of Rijndael: AES - The Advanced Encryption Standard" by Vincent Rijmen 
        /// and Joan Daemen.
        /// <param name="b">The polynomial b(x) represented by a byte.</param>
        /// <returns>The value x * b(x) mod m(x).</returns>
        public static byte XTime(byte b)
        {
            // (from p.53)
            //            8       7      6       5      4      3       2       1
            // b * x = b x  ⊕ b x ⊕ b x  ⊕ b x  ⊕ b x ⊕ b x  ⊕ b x  ⊕ b x 
            //          7       6      5      4       3      2      1       0

            // When we modulo m(x), we realize that it's a left shift
            byte top = (byte) ((b << 1) & 0xFF);

            // plus an xor to this polynomial if b7 is set:
            // x^4 ⊕ x^3 ⊕ x ⊕ 1
            // = 11011
            // = 0x1B
            bool highBitIsSet = (0x80 & b) == 0x80;

            // In order to prevent a timing attack, we'd want to make sure both
            // cases took the same amount of time
            byte bottom = highBitIsSet ? (byte) 0x1B : (byte) 0;

            byte sum = (byte) (top ^ bottom);
            return sum;
        }

        private static byte XPlus1Time(byte b)
        {
            // x ⊕ 1 = 0x03, which is a generator in x^8 ⊕ x^4 ⊕ x^3 ⊕ x ⊕ 1,
            // for more info, see http://www.samiam.org/galois.html

            // (x ⊕ 1) * b = x * b ⊕ 1 * b = x*b 
            return (byte) (XTime(b) ^ b);
        }
        
        /// <summary>
        /// Calculates the logarithm in the Rijndael finite field using (x⊕1) as the base.
        /// </summary>
        /// <param name="x">Polynomial to get the logarithm of.</param>
        /// <returns>The logarithm of <paramref name="x"/>.</returns>
        public static byte Log(byte x)
        {
            if (_LogTable == null)
            {
                _LogTable = CalculateLogTable(out _AntiLogTable);
            }

            return _LogTable[x];
        }

        /// <summary>
        /// Calculates the inverse logarithm in the Rijndael finite field using (x⊕1) as the base.
        /// </summary>
        /// <param name="x">Polynomial to get the inverse logarithm of.</param>
        /// <returns>The inverse logarithm of <paramref name="x"/>.</returns>
        public static byte AntiLog(byte x)
        {
            if (_AntiLogTable == null)
            {
                _LogTable = CalculateLogTable(out _AntiLogTable);
            }

            return _AntiLogTable[x];
        }

        /// <summary>
        /// Calculates the logarithm and inverse logarithm (antilog) in the Rijndael
        /// finite field using (x⊕1) as the base/generator.
        /// </summary>
        /// <param name="antiLogTable">The antilog table</param>
        /// <returns>The logarithm table.</returns>
        private static byte[] CalculateLogTable(out byte[] antiLogTable)
        {
            byte[] logTable = new byte[256];
            antiLogTable = new byte[256];

            antiLogTable[0] = 1;
            logTable[0] = 0;


            for (int i = 1; i < 256; i++)
            {
                // Since (x⊕1) is a generator, we can keep multiplying our previous
                // result by (x⊕1) and eventually we'll generate every element.
                antiLogTable[i] = XPlus1Time(antiLogTable[i - 1]);
                logTable[antiLogTable[i]] = (byte) i;
            }

            logTable[1] = 0;
            return logTable;
        }

        /// <summary>
        /// Calculates f(<paramref name="a"/>), which is an affine transform (e.g. it's a matrix
        /// multiply followed by a vector add).
        /// </summary>
        /// <param name="a">The byte to apply the transform to.</param>
        /// <returns>The result of F(<paramref name="a"/>)</returns>
        public static byte F(byte a)
        {
            if (_FTable == null)
            {
                _FTable = CalculateFTable(out _InvFTable);
            }

            // Uses cached copy
            return _FTable[a];
        }

        /// <summary>
        /// Calculates f(<paramref name="a"/>), which is an affine transform (e.g. it's a matrix
        /// multiply followed by a vector add).
        /// </summary>
        /// <param name="a">The byte to apply the transform to.</param>
        /// <returns>The result of F(<paramref name="a"/)</returns>
        private static byte CalculateF(byte a)
        {
            // Visually, b = f(a) is
            //
            // | b7 |   | 1 1 1 1 1 0 0 0 |   | a7 |   | 0 |
            // | b6 |   | 0 1 1 1 1 1 0 0 |   | a6 |   | 1 |
            // | b5 |   | 0 0 1 1 1 1 1 0 |   | a5 |   | 1 |
            // | b4 | * | 0 0 0 1 1 1 1 1 | * | a4 | + | 0 |
            // | b3 |   | 1 0 0 0 1 1 1 1 |   | a3 |   | 0 |
            // | b2 |   | 1 1 0 0 0 1 1 1 |   | a2 |   | 0 |
            // | b1 |   | 1 1 1 0 0 0 1 1 |   | a1 |   | 1 |
            // | b0 |   | 1 1 1 1 0 0 0 1 |   | a0 |   | 1 |

            // Define the top row of the matrix
            int[] shouldMultiplyBits = {1, 1, 1, 1, 1, 0, 0, 0};

            // Create a function that converts the 1's and 0's to bits
            Func<int[], BitArray> toBitArray = vector => new BitArray(vector.Select(b => b != 0).ToArray());
            BitArray shouldMultiply = toBitArray(shouldMultiplyBits);

            // Convert a to bits
            BitArray aVector = new BitArray(new[] {a});

            BitArray multiplyResult = new BitArray(8);

            // Perform the multiply 
            for (int offset = 0; offset < 8; offset++)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    bool currentMultiplyBitValue = shouldMultiplyBits[(8 + ((8 - offset) + bit))%8] != 0;
                    bool currentBitMultiplyResult = currentMultiplyBitValue && aVector[7 - bit];
                    if (currentBitMultiplyResult)
                    {
                        multiplyResult[offset] = !multiplyResult[offset];
                    }
                }
            }

            // Perform the vector add, which is a simply xor
            int[] affineVectorBits = {0, 1, 1, 0, 0, 0, 1, 1};
            BitArray affineVector = toBitArray(affineVectorBits);

            BitArray resultVector = multiplyResult.Xor(affineVector);

            // We have the bits, now convert them back to a byte, we do this
            // by OR-ing each bit to the value its position represents (if it is a 1).
            byte result = 0;
            byte multiplier = 0x80;

            for (int i = 0; i < 8; i++)
            {
                if (resultVector[i])
                {
                    result |= multiplier;
                }
                multiplier >>= 1;
            }

            return result;
        }

        /// <summary>
        /// Computes a table for f(a) along with its inverse.
        /// </summary>
        /// <param name="invFTable">A table for the inverse of f(a). That is g, such that f(g(a)) = a.</param>
        /// <returns>A table for f(a).</returns>
        private static byte[] CalculateFTable(out byte[] invFTable)
        {
            var result = new byte[256];
            invFTable = new byte[256];

            for (int i = 0; i < 256; i++)
            {
                result[i] = CalculateF((byte) i);
                invFTable[result[i]] = (byte) i;
            }

            return result;
        }

        /// <summary>
        /// Multiplies two polynomials (each represented by a byte) in the Rijndael finite field.
        /// </summary>
        /// <param name="left">The first polynomial.</param>
        /// <param name="right">The second polynomial.</param>
        /// <returns><paramref name="left"/>*<paramref name="right"/></returns>
        public static byte Multiply(byte left, byte right)
        {
            if (_LogTable == null)
            {
                _LogTable = CalculateLogTable(out _AntiLogTable);
            }

            if ((left != 0) && (right != 0))
            {
                byte result = _AntiLogTable[(_LogTable[left] + _LogTable[right])%255];
                return result;
            }
            else
            {
                // Multiplying anything by 0 is 0.
                // Note that we potentially have a timing attack here since this path is different than the non-zero path
                return 0;
            }
        }

        /// <summary>
        /// Computes g(a) which is the inverse in the Rijndael field such that g(a) * a = 1.
        /// </summary>        
        /// <returns>g(a)</returns>
        public static byte G(byte a)
        {
            if (_GTable == null)
            {
                _GTable = CalculateGTable();
            }

            // We have it cached
            return _GTable[a];
        }

        /// <summary>
        /// Computes g(a) which is the inverse in the Rijndael field such that g(a) * a = 1.
        /// </summary>        
        /// <returns>g(a)</returns>
        private static byte CalculateG(byte a)
        {
            // 0 doesn't have an inverse
            if (a == 0)
            {
                return 0;
            }

            // We do a brute-force search for the inverse (e.g. what we can
            // multiply a by to get 1). This is reasonable since there are a max
            // of 255 choices to try. It's simpler than working out the math to
            // get the answer algebraically.
            for (int i = 1; i < 256; i++)
            {
                if (Multiply((byte) i, a) == 1)
                {
                    return (byte) i;
                }
            }

            // We should always find an inverse, so we should never get here:
            throw new InvalidOperationException();
        }

        /// <summary>
        /// Computes a table of all g(a) values.
        /// </summary>        
        /// <returns>Table of all g(a) values.</returns>
        private static byte[] CalculateGTable()
        {
            byte[] result = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                result[i] = CalculateG((byte) i);
            }

            return result;
        }
    }
}