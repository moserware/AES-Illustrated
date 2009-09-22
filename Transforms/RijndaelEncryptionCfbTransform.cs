using System;
using System.Security.Cryptography;

namespace Moserware.AesIllustrated.Transforms
{
    /// <summary>
    /// Performs Cipher-Feedback (CFB) mode encryption.
    /// </summary>
    /// <remarks>
    /// See http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher_feedback_.28CFB.29
    /// or page 200 of Applied Cryptography 2nd edition for more info.
    /// </remarks>
    internal class RijndaelEncryptionCfbTransform : RijndaelTransform
    {
        private readonly int _FeedbackIterations;
        private readonly int _FeedbackSizeInBytes;
        private readonly byte[] _LastVector;

        public RijndaelEncryptionCfbTransform(Rijndael rijndael, int feedbackSizeInBits, byte[] initializationVector,
                                              PaddingMode paddingMode)
            : base(rijndael, paddingMode)
        {
            _FeedbackSizeInBytes = feedbackSizeInBits/Constants.BitsPerByte;
            _FeedbackIterations = rijndael.BlockSize/feedbackSizeInBits;
            _LastVector = ByteUtilities.Clone(initializationVector);
        }

        protected override byte[] InternalTransformBlock(byte[] input)
        {
            byte[] actualOutput = new byte[input.Length];
            int currentByteOffset = 0;

            for (int ixIteration = 0;
                 (ixIteration < _FeedbackIterations) && (currentByteOffset < input.Length);
                 ixIteration++)
            {
                int startIterationOffset = currentByteOffset;

                // Encrypt the register
                byte[] shiftRegisterContents = _Rijndael.Encrypt(_LastVector);

                for (int ixIterationByte = 0;
                     (ixIterationByte < _FeedbackSizeInBytes) && (currentByteOffset < input.Length);
                     ixIterationByte++)
                {
                    actualOutput[currentByteOffset] =
                        (byte) (shiftRegisterContents[ixIterationByte] ^ input[currentByteOffset]);
                    currentByteOffset++;
                }

                // Shift the bytes to the left
                Buffer.BlockCopy(_LastVector, _FeedbackSizeInBytes, _LastVector, 0,
                                 _LastVector.Length - _FeedbackSizeInBytes);

                // Put last ciphertext to the back
                Buffer.BlockCopy(actualOutput, startIterationOffset, _LastVector,
                                 _LastVector.Length - _FeedbackSizeInBytes, _FeedbackSizeInBytes);
            }

            return actualOutput;
        }
    }
}