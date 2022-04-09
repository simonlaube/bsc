import sys

def main():
    if len(sys.argv) == 1:
        return
    elif sys.argv[1] == 'A':
        with open('id.txt', "w") as id_file:
            data = id_file.write('device_A_name')
    elif sys.argv[1] == 'B':
        with open('id.txt', "w") as id_file:
            data = id_file.write('device_B_name')
    elif sys.argv[1] == 'C':
        with open('id.txt', "w") as id_file:
            data = id_file.write('device_C_name')

if __name__ == '__main__':
    main()
