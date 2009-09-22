namespace Moserware.AesIllustrated.Layers
{
    /// <summary>
    /// Performs the substitute bytes confusion (non-linear) step (γ).
    /// </summary>
    internal class SubBytes : Layer
    {
        public SubBytes(Settings settings)
            : base(settings)
        {
        }

        protected override void ApplyLayer(State state)
        {
            // Simply apply the brick-layer function by substituting each value with
            // its equivalent S-box value.
            state.ForEachCell((row, col) => SubstitutionBox.Value(state[row, col]));
        }

        protected override void InverseLayer(State state)
        {
            // Simply apply the brick-layer function by substituting each value with
            // its equivalent inverse S-box value.
            state.ForEachCell((row, col) => SubstitutionBox.Inverse(state[row, col]));
        }
    }
}