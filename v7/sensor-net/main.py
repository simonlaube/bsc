from ressource_manager import RessourceManager
from microssb import io

def main():
    faces = [io.LORA()]
    rm = RessourceManager(faces, './data/')
    rm.start()
    print('rm started')

if __name__ == '__main__':
    main()
