using System;
using System.Security.Cryptography;
using Moserware.AesIllustrated.Rounds;
using Moserware.AesIllustrated.Transforms;

namespace Moserware.AesIllustrated
{
    /// <summary>
    /// Main interface to the Rijndael algorithm.
    /// </summary>
    public class Rijndael
    {
        // The individual steps
        private int _BlockSizeInBits = 128;
        private FinalRound _FinalRound;
        private InitialRound _InitialRound;
        private IntermediateRound _IntermediateRound;
        private KeySchedule _KeySchedule;
        private Settings _Settings;

        public Rijndael()
            : this(ByteUtilities.GetCryptographicallyRandomBytes(256/Constants.BitsPerByte))
        {
        }

        public Rijndael(byte[] key)
        {
            Rekey(key);
        }

        public Rijndael(byte[] key, int blockSizeInBits)
        {
            _BlockSizeInBits = blockSizeInBits;
            Rekey(key);
        }

        /// <summary>
        /// Cipher key (must be a multiple of 32 bits and at least 128 bits).
        /// </summary>
        public byte[] Key
        {
            get { return _KeySchedule.Key; }
            set
            {
                if (value == null)
                {
                    // not calling it "value" since it likely will come from a static function
                    throw new ArgumentNullException("key");
                }

                _KeySchedule.Key = value;
                _Settings = new Settings(value.Length*Constants.BitsPerByte, BlockSize);
            }
        }

        /// <summary>
        /// Block size in bits.
        /// </summary>
        public int BlockSize
        {
            get { return _BlockSizeInBits; }
            set
            {
                int blockByteCount = BlockSize/Constants.BitsPerByte;

                if (((BlockSize%Constants.BitsPerByte) != 0) || ((blockByteCount%Constants.StateRows) != 0))
                {
                    throw new ArgumentException("Block size must be at least 128 bits and a valid multiple of 32 bits",
                                                "value");
                }

                _BlockSizeInBits = value;
                _Settings = new Settings(Key.Length*Constants.BitsPerByte, value);
            }
        }

        private void Rekey(byte[] key)
        {
            _KeySchedule = new KeySchedule(key, BlockSize/Constants.BitsPerByte);
            _Settings = new Settings(key.Length*Constants.BitsPerByte, BlockSize);
            _InitialRound = new InitialRound(_Settings, _KeySchedule);
            _IntermediateRound = new IntermediateRound(_Settings, _KeySchedule);
            _FinalRound = new FinalRound(_Settings, _KeySchedule);
        }

        /// <summary>
        /// Encrypts a single block.
        /// </summary>
        /// <param name="input">Block to encrypt.</param>
        /// <returns>Encrypted block</returns>
        public byte[] Encrypt(byte[] input)
        {
            State state = new State(input);

            if (Debugging.IsEnabled)
            {
                Debugging.Trace("Encrypting these plaintext bytes:");
                ByteUtilities.WriteBytes(input);
                Debugging.Trace("");
                Debugging.Trace("Initial state:");
                Debugging.Trace(state.ToString());
                Debugging.Trace("");
            }

            _InitialRound.Apply(state, 0);

            int totalRounds = _Settings.Rounds;
            for (int round = 1; round < totalRounds; round++)
            {
                _IntermediateRound.Apply(state, round);
            }

            _FinalRound.Apply(state, totalRounds);

            byte[] encryptedBytes = state.ToByteArray();
            
            if(Debugging.IsEnabled)
            {
                Debugging.Trace("Encryption resulted in this ciphertext:");
                ByteUtilities.WriteBytes(encryptedBytes);
            }

            return encryptedBytes;
        }

        /// <summary>
        /// Encrypts a single block.
        /// </summary>
        /// <param name="input">Block to encrypt.</param>
        /// <param name="key">Cipher key</param>
        /// <returns>Encrypted block</returns>
        public static byte[] Encrypt(byte[] input, byte[] key)
        {
            return (new Rijndael(key, input.Length * Constants.BitsPerByte)).Encrypt(input);
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
            return RijndaelEncryptionTransformFactory.Create(this, cipherMode, initializationVector, feedbackSizeInBits,
                                                             paddingMode);
        }

        /// <summary>
        /// Decrypts a single block.
        /// </summary>
        /// <param name="input">Block to decrypt.</param>
        /// <returns>The decrypted block.</returns>
        public byte[] Decrypt(byte[] input)
        {
            // Decryption does everything in reverse
            State state = new State(input);
            int totalRounds = _Settings.Rounds;

            _FinalRound.Inverse(state, totalRounds);

            for (int round = (totalRounds - 1); round > 0; round--)
            {
                _IntermediateRound.Inverse(state, round);
            }

            _InitialRound.Inverse(state, 0);

            return state.ToByteArray();
        }

        /// <summary>
        /// Decrypts a single block.
        /// </summary>
        /// <param name="input">Block to decrypt.</param>
        /// <param name="key">Cipher key</param>
        /// <returns>The decrypted block.</returns>
        public static byte[] Decrypt(byte[] input, byte[] key)
        {
            return (new Rijndael(key, input.Length * Constants.BitsPerByte)).Decrypt(input);
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
            return RijndaelDecryptionTransformFactory.Create(this, cipherMode, initializationVector, feedbackSizeInBits,
                                                             paddingMode);
        }
    }
}