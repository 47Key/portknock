
import argparse
from scanner import Scanner

# Multithreading logic
N_THREADS = 200

def parse_args():
    parser = argparse.ArgumentParser(description="A simple port scanner")
    parser.add_argument("target", help="The ip or subnet target to scan")
    parser.add_argument("-r", "--range", default="1-65535", help="The range of ports to scan in format start-end")
    parser.add_argument("-m", "--mode", choices=["quiet", "normal", "insane", "popular"], default="normal", help="The scanning mode")
    parser.add_argument("-t", "--threads", type=int, default=200, help="Number of threads to use")
    parser.add_argument("-o", "--output", type=bool, default=False, help="Whether to output the results to a file")
    parser.add_argument("-f", "--format", type=str, default='json', help="The format of the output file")
    
    return parser.parse_args()    

if __name__ == "__main__":
    args = parse_args()
    print("Scanner args: ", args)
    
    target, range, mode, output, format, threads = args.target, args.range, args.mode, args.output, args.format, args.threads
    scanner = Scanner(target, range, mode, output, format, threads)
    scanner.start()