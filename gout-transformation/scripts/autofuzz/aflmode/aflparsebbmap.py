#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

def parse_covered_by_bitmap(path):
    res = []
    f = open(path, "rb")
    buf = f.read()
    f.close()
    for i in range(len(buf)):
        # print(type(buf[i]))
        # sys.exit(0)
        if chr(buf[i]) != '\0':
            res.append(i)

    return res


if __name__ == '__main__':
    newbbmap = sys.argv[2]
    newcover = parse_covered_by_bitmap(newbbmap)

    if len(sys.argv) > 3:
        oldbbmap = sys.argv[3]    
        oldcover = parse_covered_by_bitmap(oldbbmap)
        print(len(newcover), len(oldcover))
    else:
        print(sys.argv[1], len(newcover))
    

    