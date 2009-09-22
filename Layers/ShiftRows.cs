namespace Moserware.AesIllustrated.Layers
{
    /// <summary>
    /// Performs the shift rows diffusion (linear) step (π).
    /// </summary>
    internal class ShiftRows : Layer
    {
        private readonly int[] _Shifts;

        public ShiftRows(Settings settings)
            : base(settings)
        {
            _Shifts = Constants.GetShifts(settings.BlockColumns);
        }

        protected override void ApplyLayer(State state)
        {
            // Shift the rows left
            PerformShift(state, -1);
        }

        protected override void InverseLayer(State state)
        {
            // Shift the rows right
            PerformShift(state, 1);
        }

        private void PerformShift(State state, int shiftMultiplier)
        {
            // Shifts rows by the amount specified in the _Shifts array
            // Shifting to the right is positive (+) and shifting to the
            // left is negative (-). Thus, we can use the same shift function,
            // put parameterize it with a multiplier
            for (int row = 1; row < state.Rows; row++)
            {
                byte[] shiftedRow = new byte[state.Columns];
                int currentRowShift = -1*shiftMultiplier*_Shifts[row];
                ByteMatrixRow currentRow = state.GetRow(row);

                for (int column = 0; column < state.Columns; column++)
                {
                    // Shift the row
                    shiftedRow[column] = currentRow[(currentRowShift + column + state.Columns)%state.Columns];
                }

                // Copy the result back to the state matrix
                for (int column = 0; column < state.Columns; column++)
                {
                    currentRow[column] = shiftedRow[column];
                }
            }
        }
    }
}