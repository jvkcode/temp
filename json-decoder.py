#!/usr/bin/env python

from __future__ import print_function
import sys
import json

def print_key(k1,k2):
	return print("%s:%s" %(k1,k2))

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
	# FIXME: filter out duplicates in this loop
	# to avoid duplicates
	#seen = dict()
	for pkg_name in data:
		#print("DEBUG: %s: %s\n" %(pkg_name, data[pkg_name]))
		cve = data[pkg_name]
		for c in cve:
			#print("DEBUG: %s: %s\n" % (c, cve[c]))
			keys = cve[c]
			for k in keys:
				#print("DEBUG: %s: %s\n" % (k, keys[k]))
				if 'jessie' in keys['releases']:
					# to avoid duplicates
					#key_new = print_key
					#if key_new not in seen:
					#	seen[key_new] = 1
					if 'description' in keys:
						print("%s: %s: %s\n" %(pkg_name, c, keys['description']))
					else:
						print("%s: %s: No description\n" %(pkg_name, c))

if __name__ == '__main__': main()
