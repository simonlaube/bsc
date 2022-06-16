import os
import shutil

# files not loaded to lopys
black_listed_files = ['init_pycoms.py', 'init_test_nodes.py', 'prepare_for_pycom.py', 'tests.py', 'start_test_node.py']

main = '/'
tinyssb = '/tinyssb'
pure = '/pure25519'
data = '/data'
srcs = [main, tinyssb, pure]
src = '.'

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
        os.mkdir(dest + tinyssb)
        # os.mkdir(dest + tinyssb)
        os.mkdir(dest + pure)
        os.mkdir(dest + data)
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
