using System;

namespace Datagrammer.Quic.Protocol.Packet.Frame
{
    public readonly struct NewTokenFrame
    {
        private NewTokenFrame(PacketToken token)
        {
            Token = token;
        }

        public PacketToken Token { get; }

        public static bool TryParse(ReadOnlyMemory<byte> bytes, out NewTokenFrame result, out ReadOnlyMemory<byte> remainings)
        {
            result = new NewTokenFrame();
            remainings = ReadOnlyMemory<byte>.Empty;

            if (!FrameType.TryParseFrameType(bytes, out var type, out var afterTypeRemainings))
            {
                return false;
            }

            if (!type.IsNewToken())
            {
                return false;
            }

            if(!PacketToken.TryParse(afterTypeRemainings, out var token, out var afterTokenBytes))
            {
                return false;
            }
            
            result = new NewTokenFrame(token);
            remainings = afterTokenBytes;

            return true;
        }
    }
}
