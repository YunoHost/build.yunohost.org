#!/usr/bin/env python3

import json
import sys
import os

usage = """
Usage :  ./update-images.py image-id new-version ./path/to/image.tar.gz 
"""
if len(sys.argv) < 4:
    print(usage)
    sys.exit(1)

os.chdir("/var/www/build/")

def main():

    image_id = sys.argv[1]
    version  = sys.argv[2]
    path     = sys.argv[3]

    j = json.loads(open("images.json").read())

    if image_id not in [ i["id"] for i in j ]:
        raise Exception("This image id does not already exists in the json.")

    for infos in j:
        if infos["id"] != image_id:
            continue
            
        old_file = infos["file"]

        infos.update({
            "version": "v."+version,
            "file": path
        })
        break

    os.system("rm -f %s.sig %s.sha256sum" % (path,path))

    # Generate sum
    print("Compute checksum...")
    os.system("sha256sum %s > %s.sha256sum" % (path, path))
    
    # Sign image
    print("Signing file ...")
    os.system("gpg --output %s.sig --detach-sig %s" % (path, path))

    open("images.json","w").write(json.dumps(j, sort_keys=True, indent=4, separators=(',', ': ')))
   
    if old_file != path and os.path.exists(old_file):
        os.system("mv %s %s.sig %s.sha256sum releases_archive/" % (old_file, old_file, old_file))
main()
