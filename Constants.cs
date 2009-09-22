namespace Moserware.AesIllustrated
{
    /// <summary>
    /// Constants used by Rijndael/AES.
    /// </summary>
    internal static class Constants
    {
        public const int BitsPerByte = 8;
        public const int MaxBlockSizeColumns = 8;
        public const int MaxKeySizeColumns = 8;
        public const int MaxRounds = 14;
        public const int MinKeySizeColumns = 4;
        public const int MinRounds = 10;
        public const int MinStateColumns = 4;
        public const int StateRows = 4;

        private static readonly int[][] _Shifts
            = new[]
                  {
                      new[] {0, 1, 2, 3},
                      new[] {0, 1, 2, 3},
                      new[] {0, 1, 2, 3},
                      new[] {0, 1, 2, 4},
                      new[] {0, 1, 3, 4}
                  };

        public static readonly int[] AesValidKeySizes = new[] {128, 192, 256};
        public const int AesBlockSize = 128;

        /// <summary>
        /// Gets an array of round constants (known as rcon in literature) used by the key schedule.
        /// </summary>
        /// <param name="maxRound">The maximum number of rounds needed.</param>
        /// <returns>An array of round constants (known as rcon in literature) used by the key schedule.</returns>
        public static byte[] GetRoundConstants(int maxRound)
        {
            byte[] result = new byte[maxRound];
            result[0] = 0;
            result[1] = 0x01;
            for (int i = 2; i < maxRound; i++)
            {
                result[i] = FiniteFieldMath.XTime(result[i - 1]);
            }

            return result;
        }

        // This is for the full Rijndael where the number of rounds
        // depends on the block and key size like this:
        // | 10 11 12 13 14 |
        // | 11 11 12 13 14 |
        // | 12 12 12 13 14 | Key Size (128 - 256 bits)
        // | 13 13 13 13 14 |
        // | 14 14 14 14 14 |
        //   Block Size (128 - 256 bits)

        private static int[,] GetNumberOfRoundsLookupTable()
        {
            const int MaxRows = 5;
            const int MaxCols = 5;
            int[,] result = new int[MaxRows,MaxCols];

            for (int col = 0; col < MaxCols; col++)
            {
                int rounds = MinRounds + col;
                for (int row = 0; row < col; row++)
                {
                    result[row, col] = rounds;
                    result[col, row] = rounds;
                }
                result[col, col] = rounds;
            }

            return result;
        }

        /// <summary>
        /// Gets the number of rounds needed for the given key size and block size.
        /// </summary>
        /// <param name="keySizeInColumns">The size of the key in 4 byte columns.</param>
        /// <param name="blockSizeInColumns">The size of the block in 4 byte columns.</param>
        /// <returns>The total number of rounds needed.</returns>
        public static int GetRounds(int keySizeInColumns, int blockSizeInColumns)
        {
            var table = GetNumberOfRoundsLookupTable();
            return table[keySizeInColumns - 4, blockSizeInColumns - 4];
        }

        /// <summary>
        /// Gets the amount to shift each row in the ShiftRows layer for a state matrix with the given number of columns.
        /// </summary>
        /// <param name="stateColumns">The total number of columns.</param>
        /// <returns>The amount to shift each of the 4 rows in the ShiftRows layer.</returns>
        public static int[] GetShifts(int stateColumns)
        {
            return _Shifts[stateColumns - MinStateColumns];
        }
    }
}