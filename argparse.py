import argparse

def main(args):
    rootdir = args.dir
    if not os.path.isdir(rootdir):
        print("Please give a correct directory.")
        return

    if args.t:
        pass
        
    if args.m:
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='argparse', description='demo for argparse')
        
    parser.add_argument('dir')
    parser.add_argument(
        '-m',
        action='store_true',
        help='manifest',
        required=False)
    parser.add_argument(
        '-r',
        action='store_true',
        help='resources',
        required=False)


    args = parser.parse_args()

    start = clock()
    main(args)
    finish = clock()
    print('The time is %fs' % (finish - start))