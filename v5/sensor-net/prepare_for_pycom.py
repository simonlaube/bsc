import os
import shutil

black_listed_files = ['init_pycoms.py', 'init_test_nodes.py', 'prepare_for_pycom.py', 'tests.py', 'start_test_node.py']

main = '/'
tinyssb = '/tinyssb'
microssb = '/microssb'
pure = '/pure25519'
srcs = [main, tinyssb, microssb, pure]
src = '.'

# admin node dest
# dest1 = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop/pycom/admin-node')
# network node dest
# dest2 = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop/pycom/network-node')

def clear_folder(dest):
    try:
        shutil.rmtree(dest)
    except:
        print('could not delete directory')
    try:
        os.mkdir(dest)
    except:
        print('could not create directory')

def copy_source_code(dest):
    try:
        os.mkdir(dest + microssb)
        os.mkdir(dest + tinyssb)
        os.mkdir(dest + pure)
    except:
        print('could not create directories')

    for path in srcs:
        files = os.listdir(src + path)
        for fname in files:
            if not fname.endswith('.py'):
                continue
            if fname in black_listed_files:
                continue
            shutil.copy2(os.path.join(src + path, fname), dest + path)

# for dest in [dest1, dest2]:

#     # clear dirs
#     try: 
#         shutil.rmtree(dest)
#     except:
#         print('could not delete directory')
#     try:
#         os.mkdir(dest)
#         os.mkdir(dest + microssb)
#         os.mkdir(dest + tinyssb)
#         os.mkdir(dest + pure)
#     except:
#         print('could not create directories')

#     for path in srcs:
#         files = os.listdir(src + path)
#         for fname in files:
#             if not fname.endswith('.py'):
#                 continue
#             if fname in black_listed_files:
#                 print(fname)
#                 continue
#             shutil.copy2(os.path.join(src + path, fname), dest + path)

    # files = os.listdir(dest)

# TODO: Load main files
# for fname in files:
#     print(fname)