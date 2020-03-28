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

            var type = FrameType.Parse(bytes, out var afterTypeRemainings);

            if (!type.IsNewToken())
            {
                return false;
            }

            var token = PacketToken.Parse(afterTypeRemainings, out var afterTokenBytes);
            
            result = new NewTokenFrame(token);
            remainings = afterTokenBytes;

            return true;
        }
    }
}
