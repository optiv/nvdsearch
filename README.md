# nvdsearch
A National Vulnerability Database (NVD) API query tool

## Install

Clone from repo

```
$ go mod init nvdsearch
$ go mod tidy
$ go build
```
Tested with Go version 1.19.1+ 
## Usage

nvdsearch has multiple options: `cpelookup`, `cveid`, `product`, `cpe` 

```
$ ./nvdsearch -h
                   _                                _
                  | |                              | |
 _ __  __   __  __| | ___   ___   __ _  _ __   ___ | |__
| '_ \ \ \ / / / _` |/ __| / _ \ / _` || '__| / __|| '_ \
| | | | \ V / | (_| |\__ \|  __/| (_| || |   | (__ | | | |
|_| |_|  \_/   \__,_||___/ \___| \__,_||_|    \___||_| |_|
						@h0useh3ad

Usage of ./nvdsearch:
  -cpe string
    	CPE version 2.3 format (Ex: cpe:2.3:a:progress:moveit_transfer:2023.0.1:*:*:*:*:*:*:*)
  -cpelookup string
    	CPE name lookup for product (Ex: openssl or 'apache 2.4')
  -cveid string
    	CVE ID (Ex: CVE-2023-34362 or 2023-34362)
  -output string
    	Output filename
  -product string
    	Product name
  -vendor string
    	Vendor name
  -version string
    	Product version
```

### Product search

`product` search requires the -vendor -product -version flags
```
$ ./nvdsearch -vendor apache -product http_server -version 2.4.56
```

### CVE search
`cveid`search requires the -cveid flag
```
$ ./nvdsearch -cveid CVE-2023-35708
```

### CPE name lookup
`cpelookup` requires the -cpelookup flag
```
$ ./nvdsearch -cpelookup openssl
```

### CPE search
`cpe` search requires the -cpe flag (CPE format version 2.3)
```
$ ./nvdsearch -cpe 'cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*'
```

### Write to CSV
The `product`, `cveid`, and `cpe` options will write to CSV format by providing a filename with the -output flag

```
$ ./nvdsearch -vendor openssl -product -openssl -version 1.0.2k -output openssl_1.0.2k
```

