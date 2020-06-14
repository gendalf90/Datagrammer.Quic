using System;

namespace Datagrammer.Quic.Protocol.Tls.Extensions
{
    public static class UnknownExtension
    {
        public static ReadOnlyMemory<byte> SliceBytes(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            ExtensionType.Parse(bytes, out remainings);
            ExtensionPayload.Slice(remainings, out remainings);

            return bytes.Slice(0, bytes.Length - remainings.Length);
        }
    }
}
