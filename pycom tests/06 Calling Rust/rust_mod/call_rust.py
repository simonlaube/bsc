import ctypes

rust_lib = ctypes.CDLL("target/release/librust_lib.dylib")
if __name__ == '__main__':
    res = rust_lib.fast_mod(10, 3)
    print(res)