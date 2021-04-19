all::

INSTALL=install
PREFIX=/usr/local

-include bpfmap-env.mk

all:: libbpfmap.a -lm

bpfmap_mods += bpfmap
bpfmap_mods += arraymap
bpfmap_mods += hashtab
bpfmap_mods += bitmapmap
bpfmap_mods += mincountmap
bpfmap_mods += karymap
bpfmap_mods += pcsamap
bpfmap_mods += mvsketchmap
bpfmap_mods += elasticmap
bpfmap_mods += cuckoofiltermap
bpfmap_mods += elasticmap
bpfmap_mods += ldsketchmap
bpfmap_mods += test_arraymap
bpfmap_mods += foo_map
bpfmap_mods += libghthash/hash_functions
bpfmap_mods += libghthash/hash_table
bpfmap_mods += map/map
bpfmap_mods += utils

libbpfmap.a: $(bpfmap_mods:%=%.o)
	$(AR) r '$@' $(bpfmap_mods:%=%.o)
	
test_mincount: clean_test
	gcc mincountmap.c test_mincountmap.c libghthash/hash_table.c libghthash/hash_functions.c -lm -o test_mincount

test_bitmap: clean_test
	gcc bitmapmap.c test_bitmapmap.c libghthash/hash_table.c libghthash/hash_functions.c -lm -o test_bitmap

test_karymap: clean_test
	gcc karymap.c test_karymap.c libghthash/hash_table.c libghthash/hash_functions.c -lm -o test_kary

test_mvsketch: clean_test
	gcc mvsketchmap.c test_mvsketch.c map/map.c libghthash/hash_table.c libghthash/hash_functions.c -lm -o test_mvsketch

test_elasticmap: clean_test
	gcc elasticmap.c test_elasticmap.c map/map.c libghthash/hash_table.c libghthash/hash_functions.c -lm -o test_elasticmap

test_cuckoofilter: clean_test
	gcc cuckoofiltermap.c test_cuckoofiltermap.c libghthash/hash_table.c libghthash/hash_functions.c -lm -o test_cuckoofilter
	
test_ldsketch: clean_test
	gcc ldsketchmap.c test_ldsketch.c map/map.c libghthash/hash_table.c libghthash/hash_functions.c -lm -o test_ldsketch

clean_test:
	$(RM) test_mincount test_bitmap test_kary test_mvsketch test_elasticmap test_cuckoofilter test_ldsketch test_bitmap

clean: clean_test
	$(RM) *.o */*.o *.a

install:: install-headers install-libraries

install-headers::
	$(INSTALL) -m 755 -d $(PREFIX)/include
	$(INSTALL) -m 644 bpfmap.h $(PREFIX)/include

install-libraries::
	$(INSTALL) -m 755 -d $(PREFIX)/lib
	$(INSTALL) -m 644 libbpfmap.a $(PREFIX)/lib
