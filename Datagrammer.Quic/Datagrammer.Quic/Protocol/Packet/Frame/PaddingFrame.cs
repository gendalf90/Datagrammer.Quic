﻿using System;

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

        public static bool TryParse(MemoryCursor cursor)
        {
            return FrameType.TrySlice(cursor, FrameType.Padding);
        }

        public static void WriteBytes(MemoryCursor cursor)
        {
            FrameType.Padding.WriteBytes(cursor);
        }
    }
}
