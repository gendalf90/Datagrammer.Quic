using System;

namespace Datagrammer.Quic.Protocol.Tls
{
    public readonly struct PskKeyExchangeMode : IEquatable<PskKeyExchangeMode>
    {
        private readonly byte code;

        private PskKeyExchangeMode(byte code)
        {
            this.code = code;
        }

        public static PskKeyExchangeMode Parse(MemoryCursor cursor)
        {
            return new PskKeyExchangeMode(cursor.Move(1).Span[0]);
        }

        public void WriteBytes(MemoryCursor cursor)
        {
            cursor.Move(1).Span[0] = code;
        }

        public static PskKeyExchangeMode PskDheKe { get; } = new PskKeyExchangeMode(1);

        public static PskKeyExchangeMode PskKe { get; } = new PskKeyExchangeMode(0);

        public bool Equals(PskKeyExchangeMode other)
        {
            return code == other.code;
        }

        public override bool Equals(object obj)
        {
            return obj is PskKeyExchangeMode version && Equals(version);
        }

        public override int GetHashCode()
        {
            return code;
        }

        public static bool operator ==(PskKeyExchangeMode first, PskKeyExchangeMode second)
        {
            return first.Equals(second);
        }

        public static bool operator !=(PskKeyExchangeMode first, PskKeyExchangeMode second)
        {
            return !first.Equals(second);
        }
    }
}
