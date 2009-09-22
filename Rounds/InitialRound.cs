using Moserware.AesIllustrated.Layers;

namespace Moserware.AesIllustrated.Rounds
{
    /// <summary>
    /// The initial round, also known as the "whitening" round since it just
    /// applies the first round key (⊕)
    /// </summary>
    internal class InitialRound : Round
    {
        public InitialRound(Settings settings, KeySchedule keySchedule)
            : base(new AddRoundKey(settings, keySchedule))
        {
        }
    }
}