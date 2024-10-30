# Given an array insert to the end the number as nB representation
def push_as_n_bytes(arr, number, nB):
    if isinstance(number, int):
        n = nB - 1
        while n >= 0:
            arr.append((number >> (n * 8)) & 0xFF)
            n -= 1
    else:
        for var in number:
            arr.append(var)
