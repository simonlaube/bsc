import _thread
def main():

    f = open('test.txt', 'rb')
    f.seek(128)
    f.read(128)
    f.close()

def thread_B():
    while True:
        f = open('test.txt', 'rb+')
        f.seek(128)
        f.write(bytes(896))
        f.close()
        print('write')

if __name__ == '__main__':
    f = open('test.txt', 'rb+')
    f.seek(0)
    f.write(bytes(1024))
    f.close()
    i = 0
    _thread.start_new_thread(thread_B, ())
    while True:
        main()
        print(i)
        i += 1
