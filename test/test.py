#!/usr/bin/env python3

import authwert as aw


def main():

    Log(aw.__info__)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        Log(e)
