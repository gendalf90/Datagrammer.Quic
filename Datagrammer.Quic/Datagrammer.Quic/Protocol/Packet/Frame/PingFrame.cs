﻿using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public static class PingFrame
    {
        public static bool TryParse(ReadOnlyMemory<byte> bytes, out ReadOnlyMemory<byte> remainings)
        {
            return FrameType.TryParseFrameType(bytes, out var type, out remainings) && type == 1;
        }
    }
}