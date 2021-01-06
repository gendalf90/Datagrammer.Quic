using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct AckEcnCounts
    {
        public AckEcnCounts(int ect0, int ect1, int ce)
        {
            if(ect0 < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(ect0));
            }

            if (ect1 < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(ect1));
            }

            if (ce < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(ce));
            }

            Ect0 = ect0;
            Ect1 = ect1;
            Ce = ce;
        }

        public int Ect0 { get; }

        public int Ect1 { get; }

        public int Ce { get; }

        public static AckEcnCounts Parse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            remainings = default;

            return default;
        }

        public static AckEcnCounts Parse(MemoryCursor cursor)
        {
            var ect0 = cursor.DecodeVariable32();
            var ect1 = cursor.DecodeVariable32();
            var ce = cursor.DecodeVariable32();

            return new AckEcnCounts(ect0, ect1, ce);
        }

        public void Write(MemoryCursor cursor)
        {
            cursor.EncodeVariable32(Ect0);
            cursor.EncodeVariable32(Ect1);
            cursor.EncodeVariable32(Ce);
        }
    }
}
