using System;
using System.IO;
using System.Security.Cryptography;

namespace Moserware.AesIllustrated
{
    internal static class RandomizedCapiTests
    {
        private const int MaxEncryptedSizeInBytes = 32;
        private const int TestsPerConfiguration = 100;

        private static readonly CipherMode[] _ValidCipherModes = new[]
                                                                     {
                                                                         CipherMode.ECB, CipherMode.CBC, CipherMode.CFB
                                                                     };

        private static readonly PaddingMode[] _ValidPaddingModes = new[] {PaddingMode.ANSIX923, PaddingMode.PKCS7};
        private static readonly Random _WeakRandom = new Random();

        public static int PerformRandomizedTests()
        {
            int totalTests = 0;
            foreach (int keySize in Constants.AesValidKeySizes)
            {
                foreach (CipherMode cipherMode in _ValidCipherModes)
                {
                    foreach (PaddingMode paddingMode in _ValidPaddingModes)
                    {
                        for (int i = 0; i < TestsPerConfiguration; i++)
                        {
                            PerformRandomizedTest(cipherMode, paddingMode, keySize);
                            totalTests++;
                        }
                    }
                }
            }

            return totalTests;
        }

        private static void PerformRandomizedTest(CipherMode mode, PaddingMode padding, int keySize)
        {
            var aesCapi = new AesCryptoServiceProvider();
            aesCapi.Mode = mode;
            aesCapi.Padding = padding;

            aesCapi.Key = ByteUtilities.GetCryptographicallyRandomBytes(keySize/Constants.BitsPerByte);
            aesCapi.IV = ByteUtilities.GetCryptographicallyRandomBytes(128/Constants.BitsPerByte);
            var capiEncryptionTransform = aesCapi.CreateEncryptor();

            var ours = new Rijndael(aesCapi.Key);
            var ourEncryptionTransform = ours.CreateEncryptor(aesCapi.Mode, aesCapi.IV, aesCapi.FeedbackSize,
                                                              aesCapi.Padding);

            byte[] encryptedResult = PerformRandomizedTest(capiEncryptionTransform, ourEncryptionTransform, null);

            var capiDecryptionTransform = aesCapi.CreateDecryptor();
            var ourDecryptionTransform = ours.CreateDecryptor(aesCapi.Mode, aesCapi.IV, aesCapi.FeedbackSize,
                                                              aesCapi.Padding);
            byte[] decryptedResult = PerformRandomizedTest(capiDecryptionTransform, ourDecryptionTransform,
                                                           encryptedResult);
        }

        private static byte[] PerformRandomizedTest(ICryptoTransform expectedTransform, ICryptoTransform actualTransform,
                                                    byte[] vector)
        {
            using (var msExpected = new MemoryStream())
            using (var msActual = new MemoryStream())
            {
                using (var csExpected = new CryptoStream(msExpected, expectedTransform, CryptoStreamMode.Write))
                using (var csActual = new CryptoStream(msActual, actualTransform, CryptoStreamMode.Write))
                {
                    byte[] bufferToTransform = vector;
                    if (bufferToTransform == null)
                    {
                        int randomBytesToGenerate = _WeakRandom.Next(0, MaxEncryptedSizeInBytes);
                        bufferToTransform = new byte[randomBytesToGenerate];
                        _WeakRandom.NextBytes(bufferToTransform);
                    }
                    csExpected.Write(bufferToTransform, 0, bufferToTransform.Length);
                    csActual.Write(bufferToTransform, 0, bufferToTransform.Length);
                }

                byte[] expectedTransformResult = msExpected.ToArray();
                byte[] actualTransformResult = msActual.ToArray();

                ByteUtilities.AssertBytesEqual(expectedTransformResult, actualTransformResult);

                return expectedTransformResult;
            }
        }
    }
}