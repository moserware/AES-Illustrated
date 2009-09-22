using System;
using System.Security.Cryptography;

namespace Moserware.AesIllustrated.Transforms
{
    /// <summary>
    /// Base class for all Rijndael transforms.
    /// </summary>
    internal abstract class RijndaelTransform : ICryptoTransform
    {
        protected readonly PaddingMode _PaddingMode;
        protected readonly Rijndael _Rijndael;

        protected RijndaelTransform(Rijndael rijndael, PaddingMode paddingMode)
        {
            _Rijndael = rijndael;
            _PaddingMode = paddingMode;
        }

#region ICryptoTransform Members

        public bool CanReuseTransform
        {
            get { return false; }
        }

        public bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        public int InputBlockSize
        {
            get { return _Rijndael.BlockSize; }
        }

        public int OutputBlockSize
        {
            get { return _Rijndael.BlockSize; }
        }
        
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer,
                                  int outputOffset)
        {
            int blockSizeInBytes = _Rijndael.BlockSize/Constants.BitsPerByte;
            byte[] actualInput = new byte[blockSizeInBytes];

            int totalBlocks = inputCount/actualInput.Length;

            for (int currentBlockNumber = 0; currentBlockNumber < totalBlocks; currentBlockNumber++)
            {
                int blockOffset = currentBlockNumber*actualInput.Length;
                Buffer.BlockCopy(inputBuffer, inputOffset + blockOffset, actualInput, 0, blockSizeInBytes);

                byte[] actualOutput = InternalTransformBlock(actualInput);
                Buffer.BlockCopy(actualOutput, 0, outputBuffer, outputOffset + blockOffset, blockSizeInBytes);
            }

            return inputCount;
        }

        public virtual byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            int blockSizeInBytes = _Rijndael.BlockSize/Constants.BitsPerByte;
            int overflowByteCount = inputCount%blockSizeInBytes;
            int finalPaddingCount = InternalGetFinalPaddingCount(overflowByteCount, blockSizeInBytes);
            byte[] actualOutput = new byte[inputCount + finalPaddingCount];

            int bytesAlreadyTransformed = TransformBlock(inputBuffer, inputOffset, inputCount - overflowByteCount,
                                                         actualOutput, 0);

            byte[] actualFinalInput = new byte[inputCount%blockSizeInBytes];

            if ((actualFinalInput.Length > 0) || (finalPaddingCount == blockSizeInBytes))
            {
                Buffer.BlockCopy(inputBuffer, inputOffset + bytesAlreadyTransformed, actualFinalInput, 0,
                                 actualFinalInput.Length);

                byte[] actualLastBlock = InternalTransformFinalBlock(actualFinalInput, blockSizeInBytes);
                Buffer.BlockCopy(actualLastBlock, 0, actualOutput, bytesAlreadyTransformed, actualLastBlock.Length);
            }
            return actualOutput;
        }

        public void Dispose()
        {
            // NOP for now
        }
#endregion

        /// <summary>
        /// Transforms a single block of data.
        /// </summary>
        /// <param name="input">The block to transform (it will always be the block size in length).</param>
        /// <returns>Transformed (e.g. encrypted/decrypted data).</returns>
        protected abstract byte[] InternalTransformBlock(byte[] input);

        /// <summary>
        /// Transforms the last block of data.
        /// </summary>
        /// <param name="input">The block to transform.</param>
        /// <param name="blockSizeInBytes">The expected block size.</param>
        /// <returns>The result (possibly padded as needed).</returns>
        protected virtual byte[] InternalTransformFinalBlock(byte[] input, int blockSizeInBytes)
        {
            byte[] paddedInput = PaddingUtilities.ApplyPadding(_PaddingMode, input, blockSizeInBytes);
            byte[] lastBlock = InternalTransformBlock(paddedInput);
            return lastBlock;
        }

        /// <summary>
        /// Gets the total number of padding bytes that will be needed.
        /// </summary>
        /// <param name="lastBlockBytesUsed">The total number of bytes that are used by real data in the last block.</param>
        /// <param name="blockSizeInBytes">The block cipher size.</param>
        /// <returns>The total number of padding bytes that will be needed.</returns>
        protected virtual int InternalGetFinalPaddingCount(int lastBlockBytesUsed, int blockSizeInBytes)
        {
            return PaddingUtilities.GetPaddingBytesNeeded(_PaddingMode, lastBlockBytesUsed, blockSizeInBytes);
        }
    }
}