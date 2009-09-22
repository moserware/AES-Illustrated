using System;
using System.Security.Cryptography;

namespace Moserware.AesIllustrated.Transforms
{
    /// <summary>
    /// Performs Cipher Block Chaining (CBC) mode encryption.
    /// </summary>
    /// <remarks>
    /// See http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29 
    /// or page 193 of Applied Cryptography 2nd edition for more info.
    /// </remarks>
    internal class RijndaelEncryptionCbcTransform : RijndaelTransform
    {
        private readonly byte[] _LastVector;

        public RijndaelEncryptionCbcTransform(Rijndael rijndael, byte[] initializationVector, PaddingMode paddingMode)
            : base(rijndael, paddingMode)
        {
            _LastVector = ByteUtilities.Clone(initializationVector);
        }

        protected override byte[] InternalTransformBlock(byte[] input)
        {
            for (int i = 0; i < input.Length; i++)
            {
                input[i] = (byte) (_LastVector[i] ^ input[i]);
            }

            byte[] ciphertext = _Rijndael.Encrypt(input);

            Buffer.BlockCopy(ciphertext, 0, _LastVector, 0, ciphertext.Length);
            return ciphertext;
        }
    }
}