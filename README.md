# traffic_analyzer

# How to compile
<path_to>/traffic_analyzer/src$ cmake CMakeLists.txt

# How to run
Usage: traffic_analyzer [options]\
Options:\
-i <interface>  Listen on interface for packets. If not set then "any" interface will be used.\
-a              Listen on any interface for packets explicitly.\
-w <file>       Write output to file. If not set then stdout will be used.\
-b              Write output both to stdout and file.\
-d              Print debug info.\
-h              Print this help and exit.
