using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public static class UnknownExtension
    {
        public static ReadOnlyMemory<byte> SliceBytes(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            ExtensionType.Parse(bytes, out remainings);
            ExtensionLength.Slice(remainings, out remainings);

            return bytes.Slice(0, bytes.Length - remainings.Length);
        }

        public static void SliceBytes(MemoryCursor cursor)
        {
            ExtensionType.Parse(cursor);
            ExtensionLength.Slice(cursor);
        }
    }
}
