using System;
using System.Collections.Generic;
using System.Text;

namespace Datagrammer.Quic.Protocol.Packet
{
    public readonly struct PacketNumber
    {
        private readonly uint value;

        public PacketNumber(uint value)
        {
            this.value = value;
        }
    }
}
