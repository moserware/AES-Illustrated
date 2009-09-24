using System;
using System.Security.Cryptography;

namespace Moserware.AesIllustrated.Transforms
{
    internal abstract class RijndaelDecryptionTransform : RijndaelTransform
    {
        protected RijndaelDecryptionTransform(Rijndael rijndael, PaddingMode paddingMode)
            : base(rijndael, paddingMode)
        {
        }

        public override byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            int blockSizeInBytes = _Rijndael.BlockSize/Constants.BitsPerByte;
            byte[] actualOutput = new byte[inputCount];

            int bytesAlreadyTransformed = 0;

            int bytesToTransform = inputCount - blockSizeInBytes;

            if (bytesToTransform > 0)
            {
                bytesAlreadyTransformed = TransformBlock(inputBuffer, inputOffset, inputCount - blockSizeInBytes,
                                                         actualOutput, 0);
            }

            int actualBytesLeft = inputCount - bytesAlreadyTransformed;

            byte[] actualFinalInput = new byte[actualBytesLeft];

            Buffer.BlockCopy(inputBuffer, inputOffset + bytesAlreadyTransformed, actualFinalInput, 0,
                             actualFinalInput.Length);

            byte[] actualLastBlock = InternalTransformFinalBlock(actualFinalInput, blockSizeInBytes);
            Buffer.BlockCopy(actualLastBlock, 0, actualOutput, bytesAlreadyTransformed, actualLastBlock.Length);

            int bytesToTruncate = actualFinalInput.Length - actualLastBlock.Length;

            return ByteUtilities.Truncate(actualOutput, inputCount - bytesToTruncate);
        }

        protected override int InternalGetFinalPaddingCount(int lastBlockBytesUsed, int blockSizeInBytes)
        {
            return 0;
        }

        protected override byte[] InternalTransformFinalBlock(byte[] input, int blockSizeInBytes)
        {
            return PaddingUtilities.RemovePadding(_PaddingMode, InternalTransformBlock(input));
        }
    }
}