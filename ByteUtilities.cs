using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Moserware.AesIllustrated
{
    /// <summary>
    /// Helper functions for working with bytes.
    /// </summary>
    internal static class ByteUtilities
    {
        public static void WriteBytes(byte[] bytes)
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                Console.Write(bytes[i].ToString("x2"));
            }
            Console.WriteLine();
        }

        public static string ToPolynomial(this byte b)
        {
            if (b == 0x00)
            {
                return "0";
            }

            StringBuilder sb = new StringBuilder();

            byte currentBit = 0x80;

            for (int degree = 7; degree >= 1; degree--)
            {
                if ((b & currentBit) == currentBit)
                {                    
                    sb.Append("x");
                    if (degree != 1)
                    {
                        sb.Append("^");
                        sb.Append(degree);
                    }
                    sb.Append(" + ");
                }

                currentBit >>= 1;
            }

            if ((b & currentBit) == currentBit)
            {
                sb.Append("1 ");
            }

            sb.Length -= " ".Length;

            if(sb[sb.Length - 1] == '+')
            {
                sb.Length -= " +".Length;
            }
            return sb.ToString();
        }

        public static byte[] Clone(byte[] bytesToClone)
        {
            byte[] result = new byte[bytesToClone.Length];
            Buffer.BlockCopy(bytesToClone, 0, result, 0, bytesToClone.Length);
            return result;
        }

        public static byte[] GetBytes(string clipboardValue)
        {
            clipboardValue = Regex.Replace(clipboardValue, @"\s", "");
            // like "160301"                        
            byte[] result = new byte[clipboardValue.Length/2];
            for (int i = 0; i < clipboardValue.Length; i += 2)
            {
                string currentStringByte = clipboardValue.Substring(i, 2);
                byte currentByte = Convert.ToByte(currentStringByte, 16);
                result[i/2] = currentByte;
            }
            return result;
        }

        public static void AssertBytesEqual(byte[] expected, byte[] actual)
        {
            if (expected.Length != actual.Length)
            {
                Debugger.Break();
                throw new CryptographicException("The bytes were not of the expected length.");
            }

            for (int i = 0; i < expected.Length; i++)
            {
                if (expected[i] != actual[i])
                {
                    Debugger.Break();
                    throw new CryptographicException("The bytes were not identical.");
                }
            }
        }

        public static byte[] Truncate(byte[] bytes, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(bytes, 0, result, 0, count);
            return result;
        }

        public static byte[] GetCryptographicallyRandomBytes(int bytesToGet)
        {
            RandomNumberGenerator random = RandomNumberGenerator.Create();
            byte[] result = new byte[bytesToGet];
            random.GetBytes(result);
            return result;
        }
    }
}