#!/usr/bin/env python3
import sys
from tinyssb import io
from ressource_manager import RessourceManager

def main():
    faces = [io.UDP_MULTICAST(('224.1.1.1', 5000))]
    if len(sys.argv) < 2:
        return
    if sys.argv[1] == 'admin':
        print("starting admin node...")
        rm = RessourceManager(faces, './data/Admin/')
        rm.start()

    elif sys.argv[1] == 'a':
        print("starting node a...")
        rm = RessourceManager(faces, './data/NodeA/')
        rm.start()

    elif sys.argv[1] == 'b':
        print("starting node b...")
        rm = RessourceManager(faces, './data/NodeB/')
        rm.start()
        
    elif sys.argv[1] == 'c':
        print("starting node c...")
        rm = RessourceManager(faces, './data/NodeC/')
        rm.start()

if __name__ == '__main__':
    main()