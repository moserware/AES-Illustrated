namespace Moserware.AesIllustrated.Layers
{
    /// <summary>
    /// Applies the relevant round key (⊕).
    /// </summary>
    internal class AddRoundKey : Layer
    {
        private readonly KeySchedule _KeySchedule;

        public AddRoundKey(Settings settings, KeySchedule keySchedule)
            : base(settings)
        {
            _KeySchedule = keySchedule;
        }

        public override void ApplyLayer(State state, int round)
        {
            state.Xor(_KeySchedule.GetRoundKey(round));
        }

        public override void InverseLayer(State state, int round)
        {
            // We can take advantage that xor is its own inverse:
            ApplyLayer(state, round);
        }
    }
}