using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using Moserware.AesIllustrated.Transforms;

namespace Moserware.AesIllustrated
{
    /// <summary>
    /// Checks compliance against NIST Known Answer Test (KAT) Test Vectors.
    /// </summary>
    internal static class NistKnownAnswerTestVectors
    {
        public static void VerifyAllTestVectors()
        {
            int totalVectors = 0;
            foreach (string file in Directory.GetFiles(ProjectPaths.NistKnownAnswerTestVectorsDirectory, "*.txt"))
            {
                if (!NistKnownAnswerTestFileParser.IsValidTestFileName(file))
                {
                    continue;
                }
                foreach (var vector in NistKnownAnswerTestFileParser.Parse(file))
                {
                    totalVectors++;
                    switch (vector.Operation)
                    {
                        case NistKnownAnswerTestOperation.Encrypt:
                            VerifyEncrypt(vector);
                            break;
                        case NistKnownAnswerTestOperation.Decrypt:
                            VerifyDecrypt(vector);
                            break;
                    }
                }
            }

            Console.WriteLine("{0} vectors passed!", totalVectors);
        }

        private static void VerifyDecrypt(NistKnownAnswerTestVector vector)
        {
            var rijndael = new Rijndael(vector.Key);

            int feedbackSize = vector.BitLength < 128 ? 8 : vector.BitLength;

            var transform = RijndaelDecryptionTransformFactory.Create(rijndael, vector.CipherMode, vector.IV,
                                                                      feedbackSize, PaddingMode.None);
            byte[] output = new byte[vector.Ciphertext.Length];

            transform.TransformBlock(vector.Ciphertext, 0, vector.Ciphertext.Length, output, 0);
            AssertBytesEqual(vector.Plaintext, output, vector.BitLength);
        }

        private static void VerifyEncrypt(NistKnownAnswerTestVector vector)
        {
            var rijndael = new Rijndael(vector.Key);

            int feedbackSize = vector.BitLength < 128 ? 8 : vector.BitLength;

            var transform = RijndaelEncryptionTransformFactory.Create(rijndael, vector.CipherMode, vector.IV,
                                                                      feedbackSize, PaddingMode.None);

            byte[] output = transform.TransformFinalBlock(vector.Plaintext, 0, vector.Plaintext.Length);
            AssertBytesEqual(vector.Ciphertext, output, vector.BitLength);
        }

        private static void AssertBytesEqual(byte[] expected, byte[] actual, int bitLength)
        {
            if (bitLength > 1)
            {
                ByteUtilities.AssertBytesEqual(expected, actual);
            }
            else
            {
                // special case CFB test vectors that do 1 bit at a time, just treat as a byte.
                bool actualFirstBit = (actual[0] & 0x80) == 0x80;
                bool expectedBit = (expected[0] != 0);

                if (actualFirstBit != expectedBit)
                {
                    Debugger.Break();
                    throw new CryptographicException("Bytes were not what was expected");
                }
            }
        }
    }
}