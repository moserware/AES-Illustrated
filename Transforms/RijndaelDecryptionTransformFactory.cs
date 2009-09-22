using System;
using System.Security.Cryptography;

namespace Moserware.AesIllustrated.Transforms
{
    /// <summary>
    /// Factory for creating a decryption transform from a <see cref="CipherMode"/>.
    /// </summary>
    internal static class RijndaelDecryptionTransformFactory
    {
        public static RijndaelTransform Create(Rijndael rijndael, CipherMode mode, byte[] initializationVector,
                                               int feedbackSizeInBits, PaddingMode paddingMode)
        {
            switch (mode)
            {
                case CipherMode.ECB:
                    return new RijndaelDecryptionEcbTransform(rijndael, paddingMode);
                case CipherMode.CBC:
                    return new RijndaelDecryptionCbcTransform(rijndael, initializationVector, paddingMode);
                case CipherMode.OFB:
                    return new RijndaelOfbTransform(rijndael, initializationVector, paddingMode);
                case CipherMode.CFB:
                    return new RijndaelDecryptionCfbTransform(rijndael, feedbackSizeInBits, initializationVector,
                                                              paddingMode);
                default:
                    throw new NotImplementedException(mode + " has not been implemented");
            }
        }
    }
}