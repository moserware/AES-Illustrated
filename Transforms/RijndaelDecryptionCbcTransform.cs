using System;
using System.Security.Cryptography;

namespace Moserware.AesIllustrated.Transforms
{
    /// <summary>
    /// Performs Cipher Block Chaining (CBC) mode decryption.
    /// </summary>
    /// <remarks>
    /// See http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29 
    /// or page 193 of Applied Cryptography 2nd edition for more info.
    /// </remarks>
    internal class RijndaelDecryptionCbcTransform : RijndaelDecryptionTransform
    {
        private readonly byte[] _LastVector;

        public RijndaelDecryptionCbcTransform(Rijndael rijndael, byte[] initializationVector, PaddingMode paddingMode)
            : base(rijndael, paddingMode)
        {
            _LastVector = ByteUtilities.Clone(initializationVector);
        }

        protected override byte[] InternalTransformBlock(byte[] input)
        {
            byte[] plaintext = _Rijndael.Decrypt(input);

            for (int i = 0; i < input.Length; i++)
            {
                plaintext[i] = (byte) (_LastVector[i] ^ plaintext[i]);
            }

            // The input (ciphertext) becomes what is xor'd with the next block
            Buffer.BlockCopy(input, 0, _LastVector, 0, input.Length);
            return plaintext;
        }
    }
}