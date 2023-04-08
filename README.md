# fat32extractor

Fat32 extractor, extract a file from fat32 image. It can use long filenames.

I have written it to be compatible with `Arm Trusted Firmware` code. This userspace version is used to test the routines, but it can be used as a tool or example of a fat32 reader.

## Usage:

```
./fat32 IMAGFILE [FILE] [OUTPUTFILE]
```

View Image:

```
./fat32 IMAGFILE
```

Extract to stdout:
```
./fat32 IMAGFILE FILE
```

Extract to outputfile:
```
./fat32 IMAGFILE FILE OUTPUTFILE
```

Test the tool:
```
./testfat32image.sh
```

