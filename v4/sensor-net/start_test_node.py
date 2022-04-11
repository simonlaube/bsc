#!/usr/bin/env python3
import sys

def main():
    if len(sys.argv) < 2:
        return
    if sys.argv[1] == 'admin':
        print("starting admin node...")
    elif sys.argv[1] == 'a':
        print("starting node a...")
    elif sys.argv[1] == 'b':
        print("starting node b...")
    elif sys.argv[1] == 'c':
        print("starting node c...")

if __name__ == '__main__':
    main()