from ByteFuncs import *

def padding(original_string, target_len):
    current_length = len(original_string)

    if current_length <= target_len:
        zeros_to_add = target_len - current_length

        padded_string = '\0' * zeros_to_add + original_string
    else:
        padded_string = original_string

    return padded_string

class Payload:
    # packet = bytearray([])

    def __init__(self, c_id, encrypted_aes_key=None, content_size=None, file_name=None, cksum=None):
        self.packet = bytearray([])
        push_as_n_bytes(self.packet, c_id, 16)
        if encrypted_aes_key is not None:
            if isinstance(encrypted_aes_key, int):
                push_as_n_bytes(self.packet, encrypted_aes_key, 4)
            else:
                for var in encrypted_aes_key:
                    self.packet.append(var)

        if content_size is not None:
            push_as_n_bytes(self.packet, content_size, 4)

        if file_name is not None:
            padded_file_name = padding(file_name, 255)

            for c in padded_file_name:
                self.packet.append(ord(c))


        if cksum is not None:
            push_as_n_bytes(self.packet, cksum, 4)

        # self.packet = bytearray(self.packet)
