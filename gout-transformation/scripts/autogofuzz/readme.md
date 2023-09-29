# Readme

## Usage
```sh
Usage of ./autogofuzz:
  -bins string
        bins to run
  -force
        force to generate fuzzbin
  -mode int
        1: only run exists bin, 2: only gen, 3:gen and run newly builded bin (default 2)
  -projs string
        projs to fuzz
  -resname string
        name of result file (default "fuzzRes.txt")
  -workers int
        how many works to run (default 40)
  -yamldir string
        dir of yaml files
```

## Example

1. Only run fuzz with existed bins
```
 ./autogofuzz -mode=1 -bins=fuzzbinlist.txt 
```

2. Only generate new fuzz bins
```
 ./autogofuzz -mode=2 -projs=rclone
```


3. Generate new fuzz bins and run fuzz with newly generated bins
```
./autogofuzz -mode=3 -projs=beego -force=true -resname=fuzzres-beego0624.txt -workers=32
```
