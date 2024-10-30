class Response:
    # packet = bytearray([])

    def __init__(self, version, code, payload_size, payload):
        self.packet = bytearray([])
        self.packet.append(version & 0x0FF)

        self.packet.append((code >> 8) & 0x0FF)
        self.packet.append(code & 0x0FF)

        self.packet.append((payload_size >> 24) & 0xFF)
        self.packet.append((payload_size >> 16) & 0xFF)
        self.packet.append((payload_size >> 8) & 0xFF)
        self.packet.append(payload_size & 0xFF)

        # self.packet += payload[:]

        for var in payload:
            self.packet.append(var)

        self.packet = bytearray(self.packet)
