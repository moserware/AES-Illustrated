using System;
using System.Security.Cryptography;

namespace Moserware.AesIllustrated
{
    /// <summary>
    /// Implements the Advanced Encryption Standard (AES) algorithm.
    /// </summary>
    /// <remarks>
    /// See http://www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf for more info, or Google
    /// "moserware stick figure guide advanced encryption standard".
    /// </remarks>
    public class Aes
    {
        // AES is just Rijndael with fewer options to tweak.
        private readonly Rijndael _Rijndael;

        public Aes()
        {
            _Rijndael = new Rijndael();
        }

        public Aes(byte[] key)
        {
            _Rijndael = new Rijndael(key);
        }

        /// <summary>
        /// The cipher key in (must be 128, 192, or 256 bits)
        /// </summary>
        public byte[] Key
        {
            get { return _Rijndael.Key; }
            set
            {
                if (!IsValidAesKey(value))
                {
                    throw new ArgumentException("Invalid key size (must be 128, 192, or 256 bits)", "key");
                }
                _Rijndael.Key = value;
            }
        }

        /// <summary>
        /// Encrypts a block of data.
        /// </summary>
        /// <param name="input">The plaintext block.</param>
        /// <returns>The resulting ciphertext.</returns>
        public byte[] Encrypt(byte[] input)
        {
            return _Rijndael.Encrypt(input);
        }

        /// <summary>
        /// Encrypts a block of data.
        /// </summary>
        /// <param name="input">The plaintext block.</param>
        /// <param name="key">The key to use.</param>
        /// <returns>The resulting ciphertext.</returns>
        public static byte[] Encrypt(byte[] input, byte[] key)
        {
            return (new Aes(key)).Encrypt(input);
        }

        /// <summary>
        /// Creates an encryption transform that can be used by the .NET cryptography APIs.
        /// </summary>
        /// <param name="cipherMode">The mode if the cipher to use.</param>
        /// <param name="initializationVector">An initialization vector (if used by the <paramref name="cipherMode"/>, or <see langword="null"/> if not used).</param>
        /// <param name="feedbackSizeInBits">Size of the feedback register in bits for feedback modes.</param>
        /// <param name="paddingMode">The style of padding to apply to the last block.</param>
        /// <returns>An encryption transform that can be used by the .NET cryptography APIs.</returns>
        public ICryptoTransform CreateEncryptor(CipherMode cipherMode, byte[] initializationVector,
                                                int feedbackSizeInBits, PaddingMode paddingMode)
        {
            return _Rijndael.CreateEncryptor(cipherMode, initializationVector, feedbackSizeInBits, paddingMode);
        }

        /// <summary>
        /// Decrypts a block of data.
        /// </summary>
        /// <param name="input">The ciphertext block.</param>
        /// <returns>The resulting plaintext.</returns>
        public byte[] Decrypt(byte[] input)
        {
            return _Rijndael.Decrypt(input);
        }

        /// <summary>
        /// Decrypts a block of data.
        /// </summary>
        /// <param name="input">The ciphertext block.</param>
        /// <param name="key">The key to use.</param>
        /// <returns>The resulting plaintext.</returns>
        public static byte[] Decrypt(byte[] input, byte[] key)
        {
            return (new Aes(key)).Decrypt(input);
        }

        /// <summary>
        /// Creates a decryption transform that can be used by the .NET cryptography APIs.
        /// </summary>
        /// <param name="cipherMode">The mode if the cipher to use.</param>
        /// <param name="initializationVector">An initialization vector (if used by the <paramref name="cipherMode"/>, or <see langword="null"/> if not used).</param>
        /// <param name="feedbackSizeInBits">Size of the feedback register in bits for feedback modes.</param>
        /// <param name="paddingMode">The style of padding to apply to the last block.</param>
        /// <returns>An decryption transform that can be used by the .NET cryptography APIs.</returns>
        public ICryptoTransform CreateDecryptor(CipherMode cipherMode, byte[] initializationVector,
                                                int feedbackSizeInBits, PaddingMode paddingMode)
        {
            return _Rijndael.CreateDecryptor(cipherMode, initializationVector, feedbackSizeInBits, paddingMode);
        }

        private static bool IsValidAesKey(byte[] key)
        {
            // AES only allows 3 key sizes
            int keySizeInBits = key.Length*Constants.BitsPerByte;
            return (keySizeInBits == 128)
                   || (keySizeInBits == 192)
                   || (keySizeInBits == 256);
        }
    }
}