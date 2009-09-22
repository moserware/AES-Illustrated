namespace Moserware.AesIllustrated
{
    internal class Settings
    {
        public Settings(int keySizeBits, int blockSizeBits)
        {
            KeyColumns = keySizeBits/32;
            BlockColumns = blockSizeBits/32;
            Rounds = Constants.GetRounds(KeyColumns, BlockColumns);
            KeySizeBits = keySizeBits;
            BlockSizeBits = blockSizeBits;
        }

        public int Rounds { get; private set; }
        public int KeySizeBits { get; private set; }
        public int BlockSizeBits { get; private set; }
        public int BlockColumns { get; private set; }
        public int KeyColumns { get; private set; }
    }
}