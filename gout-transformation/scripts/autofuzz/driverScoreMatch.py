
import os


import driverSelection



if __name__ == "__main__":
    projDriverNums = {}
    projDriverNums['beego'] = 36
    projDriverNums['go-restful'] = 2
    projDriverNums['websocket'] = 2
    projDriverNums['protobuf'] = 2
    projDriverNums['etcd'] = 24

    os.chdir("/home/user/workspace/gowork/src/go-fdg-exmaples")

    for proj in projDriverNums:
        with open("selectedDrivers{}".format(proj), 'r') as f:
            drivers = [i.strip() for i in f.readlines()]
        driverscores = driverSelection.driverScoring(proj)
        for driver in drivers:
            for ds in driverscores:
                if ds[0] == driver:
                    print("{}, {}".format(driver, ds[1]))
                    break
