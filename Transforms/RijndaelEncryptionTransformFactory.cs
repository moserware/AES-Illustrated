using System;
using System.Security.Cryptography;

namespace Moserware.AesIllustrated.Transforms
{
    /// <summary>
    /// Factory for creating an encryption transform from a <see cref="CipherMode"/>.
    /// </summary>
    internal static class RijndaelEncryptionTransformFactory
    {
        public static RijndaelTransform Create(Rijndael rijndael, CipherMode mode, byte[] initializationVector,
                                               int feedbackSizeInBits, PaddingMode paddingMode)
        {
            switch (mode)
            {
                case CipherMode.ECB:
                    return new RijndaelEncryptionEcbTransform(rijndael, paddingMode);
                case CipherMode.CBC:
                    return new RijndaelEncryptionCbcTransform(rijndael, initializationVector, paddingMode);
                case CipherMode.OFB:
                    return new RijndaelOfbTransform(rijndael, initializationVector, paddingMode);
                case CipherMode.CFB:
                    return new RijndaelEncryptionCfbTransform(rijndael, feedbackSizeInBits, initializationVector,
                                                              paddingMode);
                default:
                    throw new NotImplementedException(mode + " has not been implemented");
            }
        }
    }
}