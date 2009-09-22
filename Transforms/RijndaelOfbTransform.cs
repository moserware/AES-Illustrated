using System;
using System.Security.Cryptography;

namespace Moserware.AesIllustrated.Transforms
{
    /// <summary>
    /// Performs Output Feedback Mode (OFB)
    /// </summary>
    /// <remarks>
    /// See http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Output_feedback_.28OFB.29
    /// or page 205 of Applied Cryptography 2nd edition for more info.
    /// </remarks>
    internal class RijndaelOfbTransform : RijndaelTransform
    {
        private readonly byte[] _LastVector;

        public RijndaelOfbTransform(Rijndael rijndael, byte[] initializationVector, PaddingMode paddingMode)
            : base(rijndael, paddingMode)
        {
            _LastVector = ByteUtilities.Clone(initializationVector);
        }

        protected override byte[] InternalTransformBlock(byte[] input)
        {
            // Not allowing the user to specify a feedback register size other than the block 
            // length for security reasons. See Applied Cryptography 2nd edition, p. 205

            byte[] output = _Rijndael.Encrypt(_LastVector);

            Buffer.BlockCopy(output, 0, _LastVector, 0, output.Length);

            for (int i = 0; i < input.Length; i++)
            {
                output[i] = (byte) (output[i] ^ input[i]);
            }

            return output;
        }
    }
}