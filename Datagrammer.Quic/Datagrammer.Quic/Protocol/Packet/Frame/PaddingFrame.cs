using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public static class PaddingFrame
    {
        public static bool TryParse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            return FrameType
                .Parse(bytes, out remainings)
                .IsPadding();
        }

        public static void WriteBytes(ref Span<byte> bytes)
        {
            FrameType
                .CreatePadding()
                .WriteBytes(ref bytes);
        }
    }
}
