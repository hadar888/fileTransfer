import base64

def decimals_in_string_to_bytes(decimals_in_string):
    decimals_in_array = decimals_in_string.split()
    real_decimals_in_array = [int(numeric_string) for numeric_string in decimals_in_array]
    res = ''.join(chr(i) for i in real_decimals_in_array)
    return bytes(res, 'utf-8')
