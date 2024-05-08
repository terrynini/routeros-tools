# MikrotikTools


## x3_parser

parse x3 and print in readable XML-like style

```
for i in `find data/x3_parser_examples -name "*.x3"`; do
python3 x3_parser.py $i
done
```

## gdb.py

hook loader and print message for observation
need to jailbreak the RouterOS first and run gdbserver for remote debugging
The script hook the send of `loader` process, and parse the M2 message, the offset is for the RouterOS v6.49.6
