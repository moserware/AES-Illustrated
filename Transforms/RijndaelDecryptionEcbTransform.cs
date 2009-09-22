using System.Security.Cryptography;

namespace Moserware.AesIllustrated.Transforms
{
    /// <summary>
    /// Performs Electronic Codebook (ECB) mode decryption.
    /// </summary>
    /// <remarks>
    /// See http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29
    /// or page 189 of Applied Cryptography 2nd edition for more info.
    /// </remarks>
    internal class RijndaelDecryptionEcbTransform : RijndaelDecryptionTransform
    {
        public RijndaelDecryptionEcbTransform(Rijndael rijndael, PaddingMode paddingMode)
            : base(rijndael, paddingMode)
        {
        }

        protected override byte[] InternalTransformBlock(byte[] input)
        {
            // ECB is a piece of cake!
            return _Rijndael.Decrypt(input);
        }
    }
}