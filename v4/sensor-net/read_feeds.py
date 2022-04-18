import sys
import os
from init_test_nodes import hex

def main():
    if len(sys.argv) < 2:
        pass # read all logs
        return
    if os.path.exists('./data/' + sys.argv[1] + '/_feeds'):
        feeds = os.listdir('./data/' + sys.argv[1] + '/_feeds')
        for feed in feeds:
            path = './data/' + sys.argv[1] + '/_feeds/' + feed
            print(path)
            if os.path.isfile(path):
                print('open')
                buf = open(path, 'rb').read()
                # buf = buf[128:]
                print(buf[120:])

if __name__ == '__main__':
    main()
