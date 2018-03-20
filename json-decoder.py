#!/usr/bin/env python2.7

from __future__ import print_function
import sys
import json

def print_key(k1,k2):
	return str("%s:%s" %(k1,k2))

def main():
	try:
		f = sys.argv[1]
	except IndexError:
		print("Missing command line argument - file name")
		return 1
	try:
		with open(f, 'r') as jsonfile:
			data = json.load(jsonfile) 

	except IOError, err:
		print("Missing command line argument - file name")
		return 1
	# filter out duplicates in this loop
	# to avoid duplicates pkg_name:cve save seen values
	seen = dict()
	for pkg_name in data:
		#print("DEBUG: %s: %s\n" %(pkg_name, data[pkg_name]))
		cve = data[pkg_name]
		for c in cve:
			#print("DEBUG: %s: %s\n" % (c, cve[c]))
			keys = cve[c]
			for k in keys:
				#print("DEBUG: %s: %s\n" % (k, keys[k]))
				#only 'jessie' records are taken
				if 'jessie' in keys['releases']:
					# to avoid duplicates - save current pkg_name:cve
					key_new = print_key(pkg_name,c)
					if key_new in seen:
						#if combination okg_name:cve has been seen - do not duplicate it
						continue
					# add new unique key
					seen[key_new] = 1
					if 'description' in keys:
						seen[key_new] = str("%s: %s: %s\n" %(pkg_name, c, keys['description']))
					else:
						seen[key_new] = str("%s: %s: No description\n" %(pkg_name, c))
	#for k in seen:
	#	print("DEBUG: %s : %s" % (k, seen[k]))
	if seen:
		for k in sorted(seen):
			print("%s" %(seen[k]))
if __name__ == '__main__': main()
