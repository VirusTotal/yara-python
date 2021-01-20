#!/usr/bin/env python3


'''
yara_mp.py
- Example implementation of a fast recursive file scanner with multiprocessing using yara-python 
- Speed reaches 50-75% of yara.c
- Works on linux, windows and mac os (uses start method "spawn")
- Runs with python 3 and 2
- Command line parameters aim to be compatible with yara.c (as far as implemented ;)
- Uses The Unlicense, do whatever you want with the code
- By arnim rupp 

Speed:
- This script is ~25% slower than yara.c with 20 rules
- It's 100% slower than yara.c with 1600 rules (strange because I would assume that a bigger percentage of the work is done in the native C part. reason could be that every worker 
  process needs it's own copy of the compiled rules in memory because they can't be shared (pickling doesn't work on C objects)

Things that could make this code faster:
- Find a way to have the compiled rules in some kind of shared memory to have more CPU cache hits. At the moment each worker process has its own compiled rules. 

TODO: 
[ ] Handle ctrl-c better


LICENSE:
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
'''

import yara
import argparse
import os
import sys
import multiprocessing
import queue
import time

def do_scan(filePath, rules):

    #print("scanning: ", filePath)

    with open(filePath, 'rb') as f:
        fileData = f.read()

    # Scan the data read from file
    try:
        matches = rules.match(data=fileData)
        if matches:
            for match in matches:
                print(match.rule, filePath)
    except Exception as e:
        print("ERROR", "FileScan", "Cannot YARA scan file: %s" % filePath)

def worker(rulesfile, work_queue):

    # here the rules can be compiled because we're after the pickling of multiprocessing
    print("Compiling rules from %s in %s" % (rulesfile, multiprocessing.current_process().name))
    rules = yara.compile(filepaths={
      'rules':rulesfile
    })

    filePath=""
    shutdown=""
    while not shutdown:
        #print('.', end='', flush=True)
        try:
            filePath = work_queue.get(block=True, timeout=0.1)
            if filePath == 'STOP':
                shutdown = True
            else:
                #print("work work", filePath)
                try:
                    do_scan(filePath, rules)
                except Exception as e:
                    print(e)
            work_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print("%s failed on %s with: %s" % (multiprocessing.current_process().name, filePath, e.message))

    return True

############################### main() ###########################################

def main():

    # code works with python2.7 but can't be set to spawn, output differs a bit and it's 15% slower
    if sys.version_info[0] >= 3:
        # spawn is the only method on win
        multiprocessing.set_start_method('spawn')

    # Argument parsing
    parser = argparse.ArgumentParser(description='yara_mp.py, the pattern matching swiss army knife in python')
    parser.add_argument('RULES_FILE', help='Path to rules file')
    parser.add_argument('DIR', help='Path to scan')
    parser.add_argument('-r','--recursive',  help='recursively search directories',  action="store_true")
    parser.add_argument('-p','--threads',  help='use the specified NUMBER of threads to scan a directory (default is number of virtual cores)',  type=int, nargs='?')

    args = parser.parse_args()

    #print("rules file: ", args.RULES_FILE)
    rulesfile = args.RULES_FILE

    if args.threads:
        max_proc = args.threads
    else: 
        # spawn as many workers as there are virtual cores (faster than number of physical cores due to the mix of IO and CPU) 
        max_proc = multiprocessing.cpu_count()

    work_queue = multiprocessing.JoinableQueue()
    processes = []

    print("Spawning %d worker processes" % max_proc )
    for w in range(max_proc):
        p = multiprocessing.Process(target=worker, args=(rulesfile, work_queue))
        p.start()
        processes.append(p)

    # wait for workers to compile rules, TODO: let them send a message when done
    time.sleep(0.1)

    for root, directories, files in os.walk(str(args.DIR), followlinks=False):

        for filename in files:
            filePath = os.path.join(root, filename)
            #print("put in queue ", filePath)
            work_queue.put(filePath)
            #print("qsize: ", work_queue.qsize())

        if not args.recursive:
            break
    print("done directory walking")

    print("waiting for scan processes to finnish")
    work_queue.join()
    for x in range(32):
        work_queue.put('STOP')
    print("cleaning up")
    work_queue.close()
    work_queue.join_thread()

if __name__ == '__main__':
    main()
    # Add support for when a program which uses multiprocessing has been frozen to produce a Windows executable. (Has been tested with py2exe, PyInstaller and cx_Freeze.)
    multiprocessing.freeze_support()

