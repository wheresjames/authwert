
import os

def loadConfig(fname):
    globals()["__info__"] = {}
    with open(fname) as f:
        lines = f.readlines()
        for line in lines:
            parts = line.strip().replace("\t", " ").split(" ")
            k = parts.pop(0).strip()
            if '#' != k[0]:
                globals()["__%s__"%k] = " ".join(parts).strip()
                globals()["__info__"][k] = " ".join(parts).strip()

def libPath(p):
    return os.path.join(os.path.dirname(__file__), p) if p else os.path.dirname(__file__)

loadConfig(libPath('PROJECT.txt'))
